"""数据库连接与会话管理（SQLite + FTS5）。"""
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import DB_PATH

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401 确保表已注册

    Base.metadata.create_all(engine)
    # SQLite 简易迁移：devices 表补 snmp_profile_id 列
    with engine.begin() as conn:
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(devices)"))}
        if "snmp_profile_id" not in cols:
            conn.execute(
                text("ALTER TABLE devices ADD COLUMN snmp_profile_id INTEGER")
            )
        # metric_samples 表补 temperature 列（板卡温度 ℃）
        mcols = {r[1] for r in conn.execute(text("PRAGMA table_info(metric_samples)"))}
        if "temperature" not in mcols:
            conn.execute(
                text("ALTER TABLE metric_samples ADD COLUMN temperature FLOAT")
            )
        # FTS5 全文检索虚表（采集结果内容）
        conn.execute(
            text(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS output_fts USING fts5(
                    device_name,
                    command,
                    content,
                    tokenize = 'unicode61'
                )
                """
            )
        )
