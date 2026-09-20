"""全局配置：路径、模式开关（持久化到 data/settings.json）。"""
import json
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUTS_DIR = DATA_DIR / "outputs"
LOGS_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "zhlwebcrt.db"
SETTINGS_PATH = DATA_DIR / "settings.json"
SECRET_KEY_PATH = DATA_DIR / "secret.key"

for d in (DATA_DIR, OUTPUTS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# 默认只读命令白名单（采集模式下放行）
DEFAULT_WHITELIST = ["show", "display", "dir", "more", "pwd", "ls", "cat", "ping"]

# 配置 diff 时忽略的噪声行（正则）
DEFAULT_DIFF_IGNORE = [
    r"^!Time:",
    r"^! Last configuration change",
    r"^! NVRAM config last updated",
    r"Building configuration",
    r"Current configuration : \d+ bytes",
    r" uptime is ",
    r"^#?\s*\d{4}-\d{2}-\d{2} ",
]

DEFAULTS = {
    "mode": "collect",  # collect=采集模式, config=配置模式
    "cmd_whitelist": DEFAULT_WHITELIST,
    "diff_ignore_patterns": DEFAULT_DIFF_IGNORE,
    "concurrency": 20,
    "connect_timeout": 15,
    "read_timeout": 120,  # 大配置（show running-config all）输出可能超过 30s
    "retry": 1,
    # 监控
    "monitor_enabled": True,
    "monitor_interval_min": 5,
    "cpu_threshold": 85,
    "mem_threshold": 85,
}

_lock = threading.Lock()
_settings: dict = {}


def load_settings() -> dict:
    global _settings
    with _lock:
        if SETTINGS_PATH.exists():
            try:
                saved = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                saved = {}
        else:
            saved = {}
        _settings = {**DEFAULTS, **saved}
        return _settings


def get_settings() -> dict:
    if not _settings:
        load_settings()
    return _settings


def update_settings(patch: dict) -> dict:
    with _lock:
        current = get_settings()
        current.update(patch)
        SETTINGS_PATH.write_text(
            json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return current


def get_mode() -> str:
    return get_settings()["mode"]


def set_mode(mode: str) -> str:
    if mode not in ("collect", "config"):
        raise ValueError("mode 必须是 collect 或 config")
    update_settings({"mode": mode})
    return mode


def get_fernet_key() -> bytes:
    """凭据加密密钥，首次运行自动生成。"""
    from cryptography.fernet import Fernet

    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    SECRET_KEY_PATH.write_bytes(key)
    try:  # Windows 下尽量隐藏
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(SECRET_KEY_PATH), 2)
    except Exception:
        pass
    return key


load_settings()
