@echo off
chcp 65001 >nul
cd /d %~dp0
title zhlwebcrt - 设备批量采集工具

if not exist .venv (
    echo [初始化] 创建虚拟环境...
    python -m venv .venv
    if errorlevel 1 (
        echo [错误] 未找到 python，请先安装 Python 3.10+ 并勾选 "Add to PATH"
        pause
        exit /b 1
    )
    echo [初始化] 安装依赖（首次较慢，请耐心等待）...
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请检查网络
        pause
        exit /b 1
    )
)

echo [启动] zhlwebcrt 服务启动中，浏览器将自动打开 http://127.0.0.1:8000
echo [提示] 关闭本窗口即停止服务
start "" http://127.0.0.1:8000
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
