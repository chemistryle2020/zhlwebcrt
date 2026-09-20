"""模式开关 + 全局设置 API。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import get_mode, get_settings, set_mode, update_settings
from ..database import get_db
from ..schemas import ModeIn, SettingsIn

router = APIRouter(prefix="/api", tags=["mode"])


@router.get("/mode")
def read_mode():
    return {"mode": get_mode()}


@router.post("/mode")
def switch_mode(body: ModeIn):
    try:
        mode = set_mode(body.mode)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"mode": mode}


@router.get("/settings")
def read_settings():
    return get_settings()


@router.post("/settings")
def write_settings(body: SettingsIn):
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    result = update_settings(patch)
    # 监控间隔等参数变更后重排监控 job
    if any(k in patch for k in ("monitor_interval_min", "monitor_enabled")):
        from ..core.scheduler import reschedule_monitor

        reschedule_monitor()
    return result


@router.get("/audit")
def audit_logs(limit: int = 200, db: Session = Depends(get_db)):
    """最近的命令审计记录。"""
    rows = db.execute(
        text(
            "SELECT id, ts, source, device_name, command, allowed, mode "
            "FROM command_logs ORDER BY id DESC LIMIT :lim"
        ),
        {"lim": limit},
    ).mappings()
    return [dict(r) for r in rows]
