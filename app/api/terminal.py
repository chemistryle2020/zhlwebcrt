"""在线终端 WebSocket API。"""
import logging
import traceback

from fastapi import APIRouter, Depends, WebSocket
from sqlalchemy.orm import Session

from ..core.terminal import terminal_ws
from ..database import get_db
from ..models import Device

logger = logging.getLogger("zhlwebcrt.terminal")

router = APIRouter(tags=["terminal"])


@router.websocket("/ws/terminal/{device_id}")
async def websocket_terminal(websocket: WebSocket, device_id: int, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if not device:
        await websocket.accept()
        await websocket.send_text("\r\n\x1b[1;31m设备不存在\x1b[0m\r\n")
        await websocket.close()
        return
    try:
        await terminal_ws(websocket, device)
    except Exception:
        logger.error("终端会话异常:\n%s", traceback.format_exc())
        raise

