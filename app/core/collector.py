"""批量采集引擎：Netmiko 并发采集、结果落盘、变更检测、FTS 索引。"""
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from sqlalchemy import text

from ..config import OUTPUTS_DIR, get_fernet_key, get_settings
from ..database import SessionLocal, engine
from ..models import Device, Task, TaskResult
from . import cmdfilter, diffing

_cancel_flags: set[int] = set()
_cancel_lock = threading.Lock()


def cancel_task(task_id: int):
    with _cancel_lock:
        _cancel_flags.add(task_id)


def _is_cancelled(task_id: int) -> bool:
    with _cancel_lock:
        return task_id in _cancel_flags


def _clear_cancel(task_id: int):
    with _cancel_lock:
        _cancel_flags.discard(task_id)


def decrypt(enc: str) -> str:
    if not enc:
        return ""
    return Fernet(get_fernet_key()).decrypt(enc.encode()).decode()


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return Fernet(get_fernet_key()).encrypt(plain.encode()).decode()


def cmd_alias(command: str) -> str:
    """命令转文件名片段：display current-configuration -> display_current-configuration"""
    alias = re.sub(r"[^\w\-]+", "_", command.strip())[:80].strip("_")
    return alias or "cmd"


def _previous_output(device_dir: Path, alias: str, exclude_task: int) -> str | None:
    """找该设备同一命令上一次采集的内容。"""
    files = sorted(
        device_dir.glob(f"*__{alias}.txt"),
        key=lambda p: p.name,
        reverse=True,
    )
    for f in files:
        try:
            tid = int(f.name.split("__")[0])
        except (ValueError, IndexError):
            continue
        if tid != exclude_task:
            try:
                return f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return None


def _collect_one(task_id: int, device_id: int, commands: list[str]):
    """采集单台设备（线程池 worker）。每个 worker 用独立 DB 会话。"""
    settings = get_settings()
    # 在本线程的会话里加载设备及凭据，提取为纯数据（避免跨会话懒加载）
    with SessionLocal() as db:
        device = db.get(Device, device_id)
        if not device:
            return
        if not device.credential:
            dev_info, cred_info = None, None
            dev_error = "设备未绑定凭据"
        else:
            dev_error = ""
        dev_info = {
            "name": device.name,
            "host": device.host,
            "port": device.port,
            "protocol": device.protocol,
            "device_type": device.device_type,
        }
        cred_info = (
            {
                "username": device.credential.username,
                "password": decrypt(device.credential.password_enc),
                "enable": decrypt(device.credential.enable_password_enc),
            }
            if device.credential
            else None
        )
        result = (
            db.query(TaskResult)
            .filter(TaskResult.task_id == task_id, TaskResult.device_name == dev_info["name"])
            .first()
        )
        if result:
            result.status = "running"
            result.started_at = datetime.now()
            db.commit()
            result_id = result.id
        else:
            result_id = None

    status, error, has_change = "success", "", False
    device_dir = OUTPUTS_DIR / dev_info["name"]
    device_dir.mkdir(parents=True, exist_ok=True)

    try:
        if dev_error:
            raise ValueError(dev_error)
        params = {
            "device_type": dev_info["device_type"],
            "host": dev_info["host"],
            "port": dev_info["port"],
            "username": cred_info["username"],
            "password": cred_info["password"],
            "conn_timeout": settings["connect_timeout"],
            "read_timeout_override": settings["read_timeout"],
        }
        if dev_info["protocol"] == "telnet" and not dev_info["device_type"].endswith("_telnet"):
            params["device_type"] = f'{dev_info["device_type"]}_telnet'
        if cred_info["enable"]:
            params["secret"] = cred_info["enable"]

        last_err: Exception | None = None
        conn = None
        for attempt in range(settings["retry"] + 1):
            try:
                conn = ConnectHandler(**params)
                break
            except (NetmikoAuthenticationException, NetmikoTimeoutException, Exception) as e:  # noqa: BLE001
                last_err = e
        if conn is None:
            raise last_err or RuntimeError("连接失败")

        try:
            if cred_info["enable"]:
                try:
                    conn.enable()
                except Exception:
                    pass
            for command in commands:
                if _is_cancelled(task_id):
                    status, error = "failed", "任务已取消"
                    break
                allowed, reason = cmdfilter.is_allowed(command)
                cmdfilter.audit("task", dev_info["name"], command, allowed)
                if not allowed:
                    # 双保险：即使任务创建时校验过，执行前再校验一次
                    raise PermissionError(f"命令被安全策略拦截: {command}（{reason}）")
                output = conn.send_command(
                    command, read_timeout=settings["read_timeout"]
                )
                alias = cmd_alias(command)
                out_file = device_dir / f"{task_id}__{alias}.txt"
                header = (
                    f"# 设备: {dev_info['name']} ({dev_info['host']})\n"
                    f"# 命令: {command}\n"
                    f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
                    f"# 任务: {task_id}\n\n"
                )
                out_file.write_text(header + output, encoding="utf-8")

                prev = _previous_output(device_dir, alias, exclude_task=task_id)
                if prev is not None and diffing.has_change(prev, output):
                    has_change = True

                with engine.begin() as raw:
                    raw.execute(
                        text(
                            "INSERT INTO output_fts (device_name, command, content) "
                            "VALUES (:d, :c, :t)"
                        ),
                        {"d": dev_info["name"], "c": command, "t": f"[task:{task_id}]\n{output}"},
                    )
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
    except NetmikoAuthenticationException:
        status, error = "failed", "认证失败：用户名或密码错误"
    except NetmikoTimeoutException:
        status, error = "failed", "连接超时：设备不可达或端口不通"
    except PermissionError as e:
        status, error = "failed", str(e)
    except Exception as e:  # noqa: BLE001
        status, error = "failed", f"{type(e).__name__}: {e}"

    with SessionLocal() as db:
        if result_id:
            result = db.get(TaskResult, result_id)
            if result:
                result.status = status
                result.error = error
                result.has_change = has_change
                result.output_dir = str(device_dir)
                result.finished_at = datetime.now()
        task = db.get(Task, task_id)
        if task:
            if status == "success":
                task.success += 1
            else:
                task.failed += 1
        db.commit()


def run_task(task_id: int, device_ids: list[int], commands: list[str]):
    """任务主入口（后台线程）：并发采集全部设备。"""
    _clear_cancel(task_id)
    settings = get_settings()
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            return
        task.status = "running"
        task.started_at = datetime.now()
        db.commit()

    try:
        with ThreadPoolExecutor(max_workers=settings["concurrency"]) as pool:
            futures = [
                pool.submit(_collect_one, task_id, did, commands) for did in device_ids
            ]
            for f in futures:
                f.result()  # worker 内部已捕获异常，这里只为等待
    finally:
        with SessionLocal() as db:
            task = db.get(Task, task_id)
            if task:
                task.status = "cancelled" if _is_cancelled(task_id) else "done"
                task.finished_at = datetime.now()
                db.commit()
        _clear_cancel(task_id)


def create_task(name: str, commands: list[str], device_ids: list[int],
                trigger: str = "manual") -> tuple[Task | None, str]:
    """创建采集任务。采集模式下校验命令白名单。返回 (任务, 错误信息)。"""
    commands = [c.strip() for c in commands if c.strip()]
    if not commands:
        return None, "命令列表为空"

    # 铁律：采集模式下，任务命令必须全部只读
    for command in commands:
        allowed, reason = cmdfilter.check(command)
        if not allowed:
            return None, f"任务被拒绝：{reason} → {command}"

    with SessionLocal() as db:
        devices = (
            db.query(Device)
            .filter(Device.id.in_(device_ids), Device.enabled.is_(True))
            .all()
        )
        if not devices:
            return None, "没有可用的设备（请检查设备选择或启用状态）"
        task = Task(
            name=name,
            commands=json.dumps(commands, ensure_ascii=False),
            total=len(devices),
            trigger=trigger,
        )
        db.add(task)
        db.flush()
        for d in devices:
            db.add(TaskResult(task_id=task.id, device_id=d.id, device_name=d.name))
        db.commit()
        db.refresh(task)
        task_id = task.id

    thread = threading.Thread(
        target=run_task, args=(task_id, [d.id for d in devices], commands), daemon=True
    )
    thread.start()

    with SessionLocal() as db:
        return db.get(Task, task_id), ""
