#!/bin/bash
# EVVP — Start backend + frontend together

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   EVVP — Early Vulnerability Verification    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

ROOT="$(cd "$(dirname "$0")" && pwd)"

# 1. Start backend
echo "▶ Starting backend (port 8000)..."
cd "$ROOT/evvp-backend"
python3 main.py --ingest-only &
BACKEND_PID=$!
sleep 2
python3 -c "
import sys, os
sys.path.insert(0, '.')
from api.server import run
run(host='0.0.0.0', port=8000)
" &
API_PID=$!

echo "  Backend PID: $BACKEND_PID"
echo "  API PID:     $API_PID"
echo ""

# 2. Start frontend
echo "▶ Starting frontend (port 5173)..."
cd "$ROOT/evvp-frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✅ All services started"
echo ""
echo "  🌐 Dashboard  →  http://localhost:5173"
echo "  🔌 API        →  http://localhost:8000/api/health"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Cleanup on exit
trap "echo ''; echo 'Stopping...'; kill $BACKEND_PID $API_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
