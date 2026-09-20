"""定时任务：APScheduler 封装，调度信息持久化在 DB，启动时加载。"""
import json
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from ..database import SessionLocal
from ..models import Device, Schedule
from . import collector

_scheduler: BackgroundScheduler | None = None


def _job_id(schedule_id: int) -> str:
    return f"schedule_{schedule_id}"


def _run_schedule(schedule_id: int):
    """定时触发：读取调度配置并创建采集任务。"""
    with SessionLocal() as db:
        sched = db.get(Schedule, schedule_id)
        if not sched or not sched.enabled:
            return
        commands = json.loads(sched.commands)
        query = db.query(Device).filter(Device.enabled.is_(True))
        if sched.device_group:
            query = query.filter(Device.group_name == sched.device_group)
        device_ids = [d.id for d in query.all()]
        sched.last_run_at = datetime.now()
        db.commit()
    if device_ids:
        collector.create_task(
            name=f"[定时] {sched.name} {datetime.now():%m-%d %H:%M}",
            commands=commands,
            device_ids=device_ids,
            trigger="schedule",
        )


def add_job(schedule: Schedule):
    if _scheduler is None:
        return
    try:
        trigger = CronTrigger.from_crontab(schedule.cron)
    except ValueError as e:
        raise ValueError(f"无效的 cron 表达式 '{schedule.cron}': {e}")
    _scheduler.add_job(
        _run_schedule,
        trigger=trigger,
        id=_job_id(schedule.id),
        args=[schedule.id],
        replace_existing=True,
    )
    if not schedule.enabled:
        _scheduler.pause_job(_job_id(schedule.id))


def remove_job(schedule_id: int):
    if _scheduler and _scheduler.get_job(_job_id(schedule_id)):
        _scheduler.remove_job(_job_id(schedule_id))


def set_enabled(schedule_id: int, enabled: bool):
    if not _scheduler:
        return
    job = _scheduler.get_job(_job_id(schedule_id))
    if job:
        _scheduler.resume_job(_job_id(schedule_id)) if enabled else _scheduler.pause_job(
            _job_id(schedule_id)
        )


def start_scheduler():
    """应用启动时调用：加载所有启用的调度。"""
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler()
    _scheduler.start()
    with SessionLocal() as db:
        for sched in db.query(Schedule).all():
            add_job(sched)


MONITOR_JOB_ID = "monitor_round"


def start_monitor():
    """注册监控轮询 job（按 settings 的间隔）。"""
    from ..config import get_settings
    from . import monitor

    if _scheduler is None:
        return
    interval = get_settings().get("monitor_interval_min", 5)
    _scheduler.add_job(
        monitor.run_round,
        trigger="interval",
        minutes=interval,
        id=MONITOR_JOB_ID,
        replace_existing=True,
        max_instances=1,
    )


def reschedule_monitor():
    """设置变更后调用，按最新间隔重排监控 job。"""
    start_monitor()  # replace_existing=True 会按新间隔重建


def next_run_time(schedule_id: int) -> str:
    if not _scheduler:
        return ""
    job = _scheduler.get_job(_job_id(schedule_id))
    if job and job.next_run_time:
        return job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
    return ""
