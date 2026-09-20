"""FastAPI 应用入口。"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import credentials, devices, mode, monitor, results, schedules, search, snmpcollect, snmpprofiles, tasks, terminal
from .core.scheduler import start_monitor, start_scheduler
from .database import init_db

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_scheduler()
    start_monitor()
    yield


app = FastAPI(title="zhlwebcrt", version="2.0.0", lifespan=lifespan)

app.include_router(credentials.router)
app.include_router(devices.router)
app.include_router(tasks.router)
app.include_router(results.router)
app.include_router(search.router)
app.include_router(schedules.router)
app.include_router(mode.router)
app.include_router(monitor.router)
app.include_router(snmpprofiles.router)
app.include_router(snmpcollect.router)
app.include_router(terminal.router)


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/terminal.html")
def terminal_page():
    return FileResponse(STATIC_DIR / "terminal.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
