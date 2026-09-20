"""在线终端：Paramiko SSH 通道 <-> WebSocket 桥接，屏幕追踪式命令过滤。

安全设计（铁律）：
- 所有按键（含 Tab 补全、方向键、↑↓ 历史）全部透传，设备原生交互体验完整；
- 设备回显流经 pyte 虚拟屏幕，回车瞬间从屏幕读出设备行缓冲的**真实内容**校验，
  不依赖任何本地输入跟踪，彻底杜绝失步逃逸；
- 违规命令：不转发回车，改发 Ctrl+C 杀掉命令行并验证行已清空；
  清不掉则强制断开会话保底——违规命令永远没有执行机会。
"""
import asyncio
import json
import logging
import re
import socket
import threading
import time
import traceback

import paramiko
import pyte
from fastapi import WebSocket, WebSocketDisconnect

from ..config import get_mode, get_settings
from ..models import Device
from . import cmdfilter
from .collector import decrypt

logger = logging.getLogger("zhlwebcrt.terminal")

BLOCK_TIP = (
    "\x1b[1;31m*** 已拦截：{reason} ***\x1b[0m\r\n"
    "\x1b[31m当前为【采集模式】，仅允许只读命令（{whitelist} 开头）。"
    "如需配置设备请切换到【配置模式】。\x1b[0m\r\n"
)
HARD_CLOSE_TIP = (
    "\r\n\x1b[1;31m*** 无法确认命令行已清除，为保护设备已强制断开会话，请重新连接 ***\x1b[0m\r\n"
)

# 翻页提示（如 ZXR10/H3C 的 "---- More ----"）
PAGER_RE = re.compile(rb"-{2,}\s*More\s*-{2,}|--More--|\bMore:\s*$", re.I)
# 设备提示符（如 asw048# 、<HUAWEI> 、[root@x ~]$ 、(config)#）
PROMPT_RE = re.compile(r"(\S+[#>$%\]])\s?(.*)$")

SETTLE_QUIET_SECS = 0.06   # 回显静止判定
SETTLE_TIMEOUT_SECS = 1.5  # 等待回显的最长时间


def open_session(device: Device):
    """建立 paramiko 连接并返回 (client, channel)。"""
    settings = get_settings()
    if not device.credential:
        raise ValueError("设备未绑定凭据")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=device.host,
        port=device.port,
        username=device.credential.username,
        password=decrypt(device.credential.password_enc),
        timeout=settings["connect_timeout"],
        look_for_keys=False,
        allow_agent=False,
    )
    chan = client.invoke_shell(term="xterm-256color")
    chan.settimeout(0.5)  # recv 阻塞 0.5s，避免空转烧 CPU
    return client, chan


class _Shared:
    """pump 线程与 async 主循环之间的共享状态（含 pyte 虚拟屏幕）。"""

    def __init__(self, cols=80, rows=24):
        self.lock = threading.RLock()
        self.set_size(cols, rows)
        self.tail = bytearray()   # 最近的原始输出（翻页识别）
        self.tail_ts = 0.0

    def set_size(self, cols, rows):
        with self.lock:
            self.screen = pyte.Screen(max(cols, 20), max(rows, 5))
            self.stream = pyte.Stream(self.screen)

    def feed(self, data: bytes):
        with self.lock:
            self.tail = (self.tail + data)[-200:]
            self.tail_ts = time.monotonic()
            try:
                self.stream.feed(data.decode("utf-8", errors="replace"))
            except Exception:  # pyte 对异常序列宽容处理
                pass

    def idle_secs(self) -> float:
        with self.lock:
            return time.monotonic() - self.tail_ts

    def output_ts(self) -> float:
        with self.lock:
            return self.tail_ts

    def pager_active(self) -> bool:
        with self.lock:
            return bool(self.tail) and self.idle_secs() < 3.0 and \
                bool(PAGER_RE.search(bytes(self.tail)))

    def current_command(self) -> str:
        """从虚拟屏幕读出当前行缓冲的命令（提示符之后、支持换行拼接）。"""
        with self.lock:
            display = list(self.screen.display)
            cy = self.screen.cursor.y
        for y in range(cy, -1, -1):
            m = PROMPT_RE.search(display[y].rstrip())
            if m:
                cmd = m.group(2)
                for yy in range(y + 1, cy + 1):  # 长命令换行拼接
                    cmd += display[yy].rstrip()
                return cmd.strip()
        return ""


async def terminal_ws(websocket: WebSocket, device: Device):
    """WebSocket 主循环（由 API 路由调用）。"""
    await websocket.accept()
    loop = asyncio.get_running_loop()
    client = chan = None
    try:
        client, chan = await loop.run_in_executor(None, open_session, device)
    except Exception as e:  # noqa: BLE001
        logger.error("open_session 失败:\n%s", traceback.format_exc())
        await websocket.send_text(f"\r\n\x1b[1;31m连接失败: {e}\x1b[0m\r\n")
        await websocket.close()
        return

    stop = threading.Event()
    shared = _Shared()

    def pump_output():
        """设备输出 → 虚拟屏幕 + 浏览器。"""
        while not stop.is_set():
            try:
                data = chan.recv(4096)
            except socket.timeout:
                continue
            except Exception:  # noqa: BLE001
                break
            if not data:
                break
            shared.feed(data)
            asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
        stop.set()

    threading.Thread(target=pump_output, daemon=True).start()

    async def wait_settled():
        """等设备回显静止（确保屏幕内容=设备真实缓冲）。"""
        deadline = time.monotonic() + SETTLE_TIMEOUT_SECS
        while time.monotonic() < deadline:
            if shared.idle_secs() >= SETTLE_QUIET_SECS:
                return
            await asyncio.sleep(0.03)

    async def wait_new_output_since(ts: float):
        """等设备对刚才的动作产生新输出，并静止（用于 kill_line 验证）。"""
        deadline = time.monotonic() + SETTLE_TIMEOUT_SECS
        while time.monotonic() < deadline:
            if shared.output_ts() >= ts:
                break
            await asyncio.sleep(0.02)
        await wait_settled()

    async def kill_line() -> bool:
        """清掉设备行缓冲的当前内容：Ctrl+C 优先，退格兜底。"""
        t0 = time.monotonic()
        chan.send("\x03")
        await wait_new_output_since(t0)
        if not shared.current_command():
            return True
        t0 = time.monotonic()
        chan.send("\x7f" * 200)
        await wait_new_output_since(t0)
        return not shared.current_command()

    mode = get_mode()
    color = "32" if mode == "collect" else "33"
    mode_name = "采集模式（只读）" if mode == "collect" else "配置模式（谨慎操作）"
    await websocket.send_text(
        f"\x1b[1;{color}m[zhlwebcrt] 已连接 {device.name} ({device.host})，"
        f"当前模式：{mode_name}\x1b[0m\r\n"
    )

    try:
        last_input_ts = 0.0      # 最近一次向设备发送输入的时间
        last_input_printable = False  # 该次输入是否含可打印字符（应有回显）
        while not stop.is_set():
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            if message.get("bytes") is not None:
                text_in = message["bytes"].decode("utf-8", errors="replace")
            else:
                raw = message.get("text") or ""
                try:
                    payload = json.loads(raw)
                except (json.JSONDecodeError, TypeError, ValueError):
                    payload = None
                if isinstance(payload, dict):
                    if payload.get("type") == "resize":
                        cols, rows = int(payload["cols"]), int(payload["rows"])
                        chan.resize_pty(width=cols, height=rows)
                        shared.set_size(cols, rows)
                        continue
                    text_in = str(payload.get("data", ""))
                else:
                    text_in = raw

            if get_mode() == "config":
                # 配置模式：全透传，回车时取屏幕内容审计
                for ch in text_in:
                    chan.send(ch)
                    if ch in ("\r", "\n"):
                        await wait_settled()
                        cmdfilter.audit("terminal", device.name,
                                        shared.current_command() or "<input>", True)
                continue

            # ===== 采集模式：透传 + 回车时屏幕校验 =====
            i = 0
            while i < len(text_in):
                ch = text_in[i]
                if shared.pager_active():
                    chan.send(text_in[i:])  # 翻页中：按键全部直发
                    break
                if ch in ("\r", "\n"):
                    # 关键防逃逸：若刚才发送的输入还没有产生回显（粘贴/极速输入时
                    # 回车与命令在同一批到达），必须先等回显上屏再读行内容，
                    # 否则读到的是旧屏幕，违规命令会被当成"空回车"放行。
                    if shared.output_ts() < last_input_ts:
                        await wait_new_output_since(last_input_ts)
                        if last_input_printable and shared.output_ts() < last_input_ts:
                            # 可打印字符始终未回显（链路异常）：无法确认行内容，
                            # 保守处理——清掉该行，绝不盲目转发回车。
                            await kill_line()
                            await websocket.send_text(
                                "\r\n\x1b[1;31m*** 设备回显超时，无法确认命令内容，"
                                "为保护设备本次回车未执行，请重试 ***\x1b[0m\r\n"
                            )
                            i += 1
                            continue
                    else:
                        await wait_settled()
                    cmd = shared.current_command()
                    if not cmd:
                        chan.send("\r")  # 空回车安全放行
                        i += 1
                        continue
                    allowed, reason = cmdfilter.check(cmd)
                    cmdfilter.audit("terminal", device.name, cmd, allowed)
                    if allowed:
                        chan.send("\r")
                    else:
                        cleared = await kill_line()
                        wl = "/".join(get_settings()["cmd_whitelist"][:4])
                        await websocket.send_text(
                            "\r\n" + BLOCK_TIP.format(reason=reason, whitelist=wl)
                        )
                        if not cleared:
                            await websocket.send_text(HARD_CLOSE_TIP)
                            logger.error("设备 %s 命令行无法清空，强制断开会话", device.name)
                            stop.set()
                    i += 1
                    continue
                # 普通按键（含 Tab、方向键、退格等）攒批一次发送，
                # 保证转义序列完整到达设备
                cr, lf = text_in.find("\r", i), text_in.find("\n", i)
                stops = [p for p in (cr, lf) if p != -1]
                end = min(stops) if stops else len(text_in)
                batch = text_in[i:end]
                chan.send(batch)
                # 时间戳取发送完成之后：之后到达的输出一定是对本次输入的响应
                last_input_ts = time.monotonic()
                last_input_printable = any(c.isprintable() for c in batch)
                i = end
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.error("终端主循环异常:\n%s", traceback.format_exc())
    finally:
        stop.set()
        try:
            chan.close()
            client.close()
        except Exception:
            pass
