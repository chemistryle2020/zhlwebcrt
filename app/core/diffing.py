"""配置版本对比：unified diff + 噪声行过滤。"""
import difflib
import re

from ..config import get_settings


def _noise_re() -> re.Pattern | None:
    patterns = get_settings().get("diff_ignore_patterns") or []
    if not patterns:
        return None
    try:
        return re.compile("|".join(f"(?:{p})" for p in patterns))
    except re.error:
        return None


def filter_noise(text: str) -> list[str]:
    """去掉时间戳、uptime 等每次采集都变的噪声行。"""
    rx = _noise_re()
    lines = text.splitlines()
    if not rx:
        return lines
    return [ln for ln in lines if not rx.search(ln)]


def has_change(old: str, new: str) -> bool:
    return filter_noise(old) != filter_noise(new)


def unified_diff(old: str, new: str, from_name: str = "上一版本", to_name: str = "本次采集") -> str:
    diff = difflib.unified_diff(
        filter_noise(old),
        filter_noise(new),
        fromfile=from_name,
        tofile=to_name,
        lineterm="",
    )
    return "\n".join(diff)
