"""采集结果 API：文件列表、查看、diff、打包下载。"""
import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..config import OUTPUTS_DIR
from ..core import diffing
from ..core.collector import cmd_alias
from ..database import get_db
from ..models import Task, TaskResult

router = APIRouter(prefix="/api/results", tags=["results"])


@router.get("/{task_id}/download")
def download_task_zip(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    results = db.query(TaskResult).filter(TaskResult.task_id == task_id).all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        summary = [f"任务: {task.name} (#{task.id})", f"时间: {task.created_at}", ""]
        for r in results:
            line = f"{r.device_name}\t{r.status}"
            if r.error:
                line += f"\t{r.error}"
            if r.has_change:
                line += "\t[配置有变更]"
            summary.append(line)
            d = OUTPUTS_DIR / r.device_name
            for f in d.glob(f"{task_id}__*.txt") if d.exists() else []:
                zf.write(f, arcname=f"{r.device_name}/{f.name}")
        zf.writestr("汇总.txt", "\n".join(summary))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=task_{task_id}_outputs.zip"},
    )


def _task_dir(task_id: int, device_name: str) -> Path:
    return OUTPUTS_DIR / device_name


def _list_outputs(task_id: int, device_name: str) -> list[dict]:
    d = _task_dir(task_id, device_name)
    if not d.exists():
        return []
    files = []
    for f in sorted(d.glob(f"{task_id}__*.txt")):
        command = f.name[len(f"{task_id}__"): -4].replace("_", " ")
        files.append({"file": f.name, "command": command, "size": f.stat().st_size})
    return files


@router.get("/{task_id}/{device_name}")
def list_device_outputs(task_id: int, device_name: str, db: Session = Depends(get_db)):
    result = (
        db.query(TaskResult)
        .filter(TaskResult.task_id == task_id, TaskResult.device_name == device_name)
        .first()
    )
    if not result:
        raise HTTPException(404, "未找到该设备的采集结果")
    return {
        "status": result.status,
        "error": result.error,
        "has_change": result.has_change,
        "files": _list_outputs(task_id, device_name),
    }


@router.get("/{task_id}/{device_name}/file/{filename}")
def read_output(task_id: int, device_name: str, filename: str):
    if ".." in filename or "/" in filename:
        raise HTTPException(400, "非法文件名")
    f = OUTPUTS_DIR / device_name / filename
    if not f.exists() or not f.name.startswith(f"{task_id}__"):
        raise HTTPException(404, "文件不存在")
    return {"content": f.read_text(encoding="utf-8", errors="replace")}


@router.get("/{task_id}/{device_name}/diff/{alias}")
def diff_output(task_id: int, device_name: str, alias: str):
    """与上一次同命令采集结果做 diff。"""
    d = OUTPUTS_DIR / device_name
    current = d / f"{task_id}__{alias}.txt"
    if not current.exists():
        raise HTTPException(404, "当前版本不存在")
    prev_files = sorted(
        (f for f in d.glob(f"*__{alias}.txt") if not f.name.startswith(f"{task_id}__")),
        key=lambda p: p.name,
        reverse=True,
    )
    if not prev_files:
        return {"has_previous": False, "diff": "", "changed": False}

    def strip_header(text: str) -> str:
        lines = text.splitlines()
        while lines and lines[0].startswith("#"):
            lines.pop(0)
        return "\n".join(lines).strip()

    old = strip_header(prev_files[0].read_text(encoding="utf-8", errors="replace"))
    new = strip_header(current.read_text(encoding="utf-8", errors="replace"))
    changed = diffing.has_change(old, new)
    diff_text = (
        diffing.unified_diff(old, new, from_name=prev_files[0].name, to_name=current.name)
        if changed
        else ""
    )
    return {"has_previous": True, "diff": diff_text, "changed": changed}
