"""采集任务 API。"""
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core import collector
from ..database import get_db
from ..models import Task, TaskResult
from ..schemas import TaskIn, TaskOut, TaskResultOut

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("", response_model=list[TaskOut])
def list_tasks(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(Task).order_by(Task.id.desc()).limit(limit).all()


@router.post("", response_model=TaskOut)
def create_task(body: TaskIn, db: Session = Depends(get_db)):
    task, error = collector.create_task(
        name=body.name, commands=body.commands, device_ids=body.device_ids
    )
    if task is None:
        raise HTTPException(400, error)
    return db.get(Task, task.id)


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    return task


@router.get("/{task_id}/detail")
def get_task_detail(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    results = (
        db.query(TaskResult)
        .filter(TaskResult.task_id == task_id)
        .order_by(TaskResult.status.desc(), TaskResult.device_name)
        .all()
    )
    return {
        "task": TaskOut.model_validate(task).model_dump(mode="json"),
        "commands": json.loads(task.commands),
        "results": [
            TaskResultOut.model_validate(r).model_dump(mode="json") for r in results
        ],
    }


@router.post("/{task_id}/cancel")
def cancel_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.status != "running":
        raise HTTPException(400, "任务不在运行中")
    collector.cancel_task(task_id)
    return {"ok": True}


@router.delete("/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.status == "running":
        raise HTTPException(400, "运行中的任务不能删除，请先取消")
    db.delete(task)
    db.commit()
    return {"ok": True}
