"""定时任务 API。"""
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core import cmdfilter, scheduler
from ..database import get_db
from ..models import Schedule
from ..schemas import ScheduleIn, ScheduleOut

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _to_out(s: Schedule) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "cron": s.cron,
        "commands": json.loads(s.commands),
        "device_group": s.device_group,
        "enabled": s.enabled,
        "last_run_at": s.last_run_at,
        "created_at": s.created_at,
        "next_run": scheduler.next_run_time(s.id),
    }


@router.get("")
def list_schedules(db: Session = Depends(get_db)):
    return [_to_out(s) for s in db.query(Schedule).order_by(Schedule.id).all()]


@router.post("", response_model=ScheduleOut)
def create_schedule(body: ScheduleIn, db: Session = Depends(get_db)):
    # 采集模式下校验命令白名单
    for command in body.commands:
        allowed, reason = cmdfilter.check(command)
        if not allowed:
            raise HTTPException(400, f"定时任务被拒绝：{reason} → {command}")
    sched = Schedule(
        name=body.name,
        cron=body.cron,
        commands=json.dumps([c.strip() for c in body.commands if c.strip()],
                            ensure_ascii=False),
        device_group=body.device_group,
        enabled=body.enabled,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    try:
        scheduler.add_job(sched)
    except ValueError as e:
        db.delete(sched)
        db.commit()
        raise HTTPException(400, str(e))
    return sched


@router.put("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: int, body: ScheduleIn, db: Session = Depends(get_db)):
    sched = db.get(Schedule, schedule_id)
    if not sched:
        raise HTTPException(404, "定时任务不存在")
    for command in body.commands:
        allowed, reason = cmdfilter.check(command)
        if not allowed:
            raise HTTPException(400, f"定时任务被拒绝：{reason} → {command}")
    sched.name = body.name
    sched.cron = body.cron
    sched.commands = json.dumps([c.strip() for c in body.commands if c.strip()],
                                ensure_ascii=False)
    sched.device_group = body.device_group
    sched.enabled = body.enabled
    db.commit()
    db.refresh(sched)
    scheduler.add_job(sched)  # replace_existing=True
    return sched


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db)):
    sched = db.get(Schedule, schedule_id)
    if not sched:
        raise HTTPException(404, "定时任务不存在")
    scheduler.remove_job(schedule_id)
    db.delete(sched)
    db.commit()
    return {"ok": True}
