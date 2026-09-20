"""命令安全过滤器 —— 采集模式下的服务端强制防线。

铁律：采集模式下，任何渠道（在线终端 / 批量任务）只允许执行
只读白名单内的命令，其余一律拦截并审计。
"""
import re
from datetime import datetime

from ..config import LOGS_DIR, get_mode, get_settings

# 即使用了只读命令也不允许出现的危险片段（重定向写文件、管道进 shell 执行等）
_DANGEROUS_FRAGMENTS = [
    r">\s*\S",        # 重定向写文件
    r">>\s*\S",
    r"\bdelete\b",
    r"\berase\b",
    r"\bformat\b",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\breload\b",
    r"\breset\b",
    r"\bundo\b",      # 华为/H3C 删配置关键字
    r"\bno\s+\S",     # 思科删配置
]
_dangerous_re = re.compile("|".join(f"({p})" for p in _DANGEROUS_FRAGMENTS), re.I)


def first_word(command: str) -> str:
    """取命令行首个有效单词（小写）。"""
    parts = command.strip().split()
    return parts[0].lower() if parts else ""


def is_allowed(command: str, whitelist: list[str] | None = None) -> tuple[bool, str]:
    """校验命令是否只读。返回 (是否放行, 原因)。"""
    cmd = command.strip()
    if not cmd:
        return True, "空命令"

    wl = [w.lower() for w in (whitelist or get_settings()["cmd_whitelist"])]
    word = first_word(cmd)

    if word not in wl:
        return False, f"命令 '{word}' 不在只读白名单内（当前为采集模式）"

    if _dangerous_re.search(cmd):
        return False, "命令中包含危险操作片段，已拦截"

    return True, "ok"


def check(command: str) -> tuple[bool, str]:
    """按当前全局模式校验。配置模式一律放行。"""
    if get_mode() == "config":
        return True, "配置模式放行"
    return is_allowed(command)


def audit(source: str, device_name: str, command: str, allowed: bool):
    """写审计日志（数据库 + 文件双写，文件兜底）。"""
    mode = get_mode()
    # 文件日志
    try:
        day = datetime.now().strftime("%Y%m%d")
        line = (
            f"{datetime.now():%Y-%m-%d %H:%M:%S}\t{mode}\t{source}\t"
            f"{device_name}\t{'ALLOW' if allowed else 'BLOCK'}\t{command}\n"
        )
        with open(LOGS_DIR / f"commands_{day}.log", "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass
    # 数据库
    try:
        from ..database import SessionLocal
        from ..models import CommandLog

        with SessionLocal() as db:
            db.add(
                CommandLog(
                    source=source,
                    device_name=device_name,
                    command=command,
                    allowed=allowed,
                    mode=mode,
                )
            )
            db.commit()
    except Exception:
        pass
