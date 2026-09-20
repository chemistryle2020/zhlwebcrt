"""全文检索 API（SQLite FTS5）。"""
from fastapi import APIRouter
from sqlalchemy import text

from ..database import engine

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
def search(q: str, device: str = "", limit: int = 100):
    """FTS5 全文检索。空格分隔多个关键词（AND）。"""
    q = q.strip()
    if not q:
        return []
    # 转义 FTS5 特殊字符，多词 AND
    terms = [t.replace('"', '""') for t in q.split() if t]
    match = " AND ".join(f'"{t}"' for t in terms)

    sql = (
        "SELECT device_name, command, "
        "snippet(output_fts, 2, '<mark>', '</mark>', '...', 64) AS snippet, "
        "rowid FROM output_fts WHERE output_fts MATCH :match"
    )
    params = {"match": match, "lim": limit}
    if device:
        sql += " AND device_name = :device"
        params["device"] = device
    sql += " ORDER BY rank LIMIT :lim"

    with engine.connect() as conn:
        try:
            rows = conn.execute(text(sql), params).mappings()
        except Exception as e:  # FTS 语法错误等
            return [{"error": str(e)}]
        hits = []
        for r in rows:
            content = r["snippet"] or ""
            task_id = None
            hits.append(
                {
                    "device_name": r["device_name"],
                    "command": r["command"],
                    "snippet": content,
                    "rowid": r["rowid"],
                }
            )
        return hits
