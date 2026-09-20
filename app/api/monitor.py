"""监控 API：大盘总览、历史曲线、告警管理。"""
import threading
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core import monitor
from ..database import get_db
from ..models import Alert, DeviceAsset, IfaceSample, MetricSample

router = APIRouter(prefix="/api/monitor", tags=["monitor"])


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    devices = monitor.latest_status()
    online = sum(1 for d in devices if d["online"] is True)
    offline = sum(1 for d in devices if d["online"] is False)
    latencies = [d["latency_ms"] for d in devices if d["latency_ms"] is not None]
    unacked = db.query(Alert).filter(Alert.acknowledged.is_(False)).count()
    return {
        "total": len(devices),
        "online": online,
        "offline": offline,
        "unknown": len(devices) - online - offline,
        "avg_latency": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "unacked_alerts": unacked,
        "devices": devices,
    }


@router.get("/history")
def history(device_name: str = "", hours: int = 6, db: Session = Depends(get_db)):
    """时序数据。不带设备名 → 全局每轮在线数/平均时延。"""
    since = datetime.now() - timedelta(hours=hours)
    q = db.query(MetricSample).filter(MetricSample.ts >= since).order_by(MetricSample.ts)
    if device_name:
        samples = q.filter(MetricSample.device_name == device_name).all()
        traffic = (
            db.query(IfaceSample)
            .filter(IfaceSample.device_name == device_name, IfaceSample.ts >= since)
            .order_by(IfaceSample.ts)
            .all()
        )
        return {
            "points": [
                {
                    "ts": s.ts.isoformat(),
                    "online": s.online,
                    "latency_ms": s.latency_ms,
                    "cpu_pct": s.cpu_pct,
                    "mem_pct": s.mem_pct,
                    "temperature": s.temperature,
                }
                for s in samples
            ],
            "traffic": [
                {
                    "ts": t.ts.isoformat(),
                    "in_bps": t.in_bps,
                    "out_bps": t.out_bps,
                    "err_in": t.err_in,
                    "err_out": t.err_out,
                }
                for t in traffic
            ],
        }
    # 全局：按轮次（分钟）聚合
    buckets: dict[str, dict] = {}
    for s in q.all():
        key = s.ts.strftime("%Y-%m-%d %H:%M")
        b = buckets.setdefault(key, {"online": 0, "lat": [], "total": 0})
        b["total"] += 1
        if s.online:
            b["online"] += 1
        if s.latency_ms is not None:
            b["lat"].append(s.latency_ms)
    return {
        "points": [
            {
                "ts": k,
                "online_count": b["online"],
                "total": b["total"],
                "avg_latency": round(sum(b["lat"]) / len(b["lat"]), 1) if b["lat"] else None,
            }
            for k, b in sorted(buckets.items())
        ]
    }


@router.get("/alerts")
def list_alerts(unacked: bool = False, limit: int = 100, db: Session = Depends(get_db)):
    q = db.query(Alert)
    if unacked:
        q = q.filter(Alert.acknowledged.is_(False))
    rows = q.order_by(Alert.id.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "ts": a.ts.isoformat(),
            "device_name": a.device_name,
            "level": a.level,
            "type": a.type,
            "message": a.message,
            "acknowledged": a.acknowledged,
        }
        for a in rows
    ]


@router.post("/alerts/{alert_id}/ack")
def ack_alert(alert_id: int, db: Session = Depends(get_db)):
    if alert_id == 0:  # 一键全部确认
        db.query(Alert).filter(Alert.acknowledged.is_(False)).update(
            {"acknowledged": True}
        )
    else:
        alert = db.get(Alert, alert_id)
        if alert:
            alert.acknowledged = True
    db.commit()
    return {"ok": True}


@router.post("/run")
def run_now():
    """立即执行一轮监控（后台线程，不阻塞请求）。"""
    threading.Thread(target=monitor.run_round, daemon=True).start()
    return {"ok": True, "message": "监控轮次已启动"}


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    """全部设备资产信息。"""
    rows = db.query(DeviceAsset).order_by(DeviceAsset.device_name).all()
    return [
        {
            "device_name": a.device_name,
            "sys_descr": a.sys_descr,
            "sys_name": a.sys_name,
            "sys_object_id": a.sys_object_id,
            "version": a.version,
            "uptime_days": a.uptime_days,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in rows
    ]
