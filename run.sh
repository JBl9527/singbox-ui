#!/bin/sh
PORT=${1:-9622}
echo "Starting Sing-Box WebUI on port $PORT..."
python3 app.py --port $PORT
