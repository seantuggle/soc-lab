#!/usr/bin/env bash
# run_local.sh — Run SOC Lab locally without Docker
# Usage:
#   chmod +x run_local.sh
#   ./run_local.sh
#
# Requirements: Python 3.10+ in PATH

set -euo pipefail

VENV=".venv"
DB_DIR="db"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         SOC Lab — Local Runner           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Create venv if needed
if [ ! -d "$VENV" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

mkdir -p "$DB_DIR"

echo "[*] Initializing database..."
python3 - <<'EOF'
import sys; sys.path.insert(0,".")
from shared.schema import init_db
init_db("db/soc.db")
print("    DB ready at db/soc.db")
EOF

echo ""
echo "[*] Starting services (Ctrl+C to stop all)..."
echo ""

# Start ingestion service
DB_PATH=db/soc.db LOG_LEVEL=$LOG_LEVEL \
  uvicorn services.ingestion.main:app --host 0.0.0.0 --port 8001 --log-level warning &
PID_INGEST=$!
echo "    ✓ Ingestion  → http://localhost:8001/health  (pid $PID_INGEST)"

sleep 2

# Start detection engine
DB_PATH=db/soc.db RULES_DIR=rules LOG_LEVEL=$LOG_LEVEL \
  python3 -m services.detection.main &
PID_DETECT=$!
echo "    ✓ Detection  → background process           (pid $PID_DETECT)"

# Start dashboard
DB_PATH=db/soc.db LOG_LEVEL=$LOG_LEVEL \
  uvicorn services.dashboard.main:app --host 0.0.0.0 --port 8080 --log-level warning &
PID_DASH=$!
echo "    ✓ Dashboard  → http://localhost:8080        (pid $PID_DASH)"

echo ""
echo "════════════════════════════════════════════"
echo "  Dashboard: http://localhost:8080"
echo "  Ingestion: http://localhost:8001/health"
echo ""
echo "  Generate events:"
echo "    python tools/generate_events.py --scenario brute_force"
echo "    python tools/generate_events.py --scenario all"
echo "════════════════════════════════════════════"
echo ""

# Cleanup on exit
cleanup() {
  echo ""
  echo "[*] Stopping services..."
  kill $PID_INGEST $PID_DETECT $PID_DASH 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[*] Done."
}
trap cleanup EXIT INT TERM

wait
