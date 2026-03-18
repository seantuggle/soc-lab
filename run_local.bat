@echo off
REM run_local.bat — Run SOC Lab locally on Windows (no Docker)
REM
REM Requirements: Python 3.10+ in PATH
REM
REM Usage: Double-click or run from a CMD/PowerShell window:
REM   run_local.bat

setlocal enabledelayedexpansion

echo.
echo ============================================
echo    SOC Lab -- Local Runner (Windows)
echo ============================================
echo.

REM ── Check Python ─────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo         Download from https://python.org and re-run.
    pause
    exit /b 1
)

REM ── Virtual environment ───────────────────────
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

REM ── Dependencies ─────────────────────────────
echo [*] Installing dependencies...
pip install -q -r requirements.txt

REM ── Database ─────────────────────────────────
if not exist "db" mkdir db
echo [*] Initializing database...
python -c "import sys; sys.path.insert(0,'.'); from shared.schema import init_db; init_db('db/soc.db'); print('    DB ready at db/soc.db')"

echo.
echo [*] Starting services...
echo     (Close this window or press Ctrl+C to stop)
echo.

REM Start ingestion in a new window
set DB_PATH=db/soc.db
set LOG_LEVEL=INFO
start "SOC-Ingestion" cmd /k "call .venv\Scripts\activate.bat && set DB_PATH=db/soc.db && uvicorn services.ingestion.main:app --host 0.0.0.0 --port 8001 --log-level warning"

REM Wait for ingestion to be ready
echo [*] Waiting for ingestion service...
timeout /t 4 /nobreak >nul

REM Start detection in a new window
start "SOC-Detection" cmd /k "call .venv\Scripts\activate.bat && set DB_PATH=db/soc.db && set RULES_DIR=rules && python -m services.detection.main"

REM Start dashboard in a new window
start "SOC-Dashboard" cmd /k "call .venv\Scripts\activate.bat && set DB_PATH=db/soc.db && uvicorn services.dashboard.main:app --host 0.0.0.0 --port 8080 --log-level warning"

timeout /t 2 /nobreak >nul

echo.
echo ============================================
echo   Dashboard:  http://localhost:8080
echo   Ingestion:  http://localhost:8001/health
echo.
echo   Generate events (new terminal):
echo     python tools\generate_events.py --scenario brute_force
echo     python tools\generate_events.py --scenario all
echo ============================================
echo.
echo Three service windows have been opened.
echo Close them to stop the lab.
echo.
pause
