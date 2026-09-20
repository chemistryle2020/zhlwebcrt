#!/usr/bin/env bash
# WSL/Linux 启动脚本
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    echo "[初始化] 创建虚拟环境..."
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip
    ./.venv/bin/pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
fi

echo "[启动] zhlwebcrt: http://127.0.0.1:18080 （Windows 浏览器直接打开即可）"
exec ./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 18080
