# SOC Lab 🔍

A complete, local Security Operations Center (SOC) learning environment.
Built in Python. Runs with one command. Designed to teach.

```
┌─────────────────────────────────────────────────────────────┐
│  Log Sources → Ingest → Normalize → Detect → Alert → Triage │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start (Docker — Recommended)

**Requirements:** Docker Desktop (Windows/Mac) or Docker Engine (Linux)

```bash
# 1. Clone / unzip the project
cd soc-lab

# 2. Start everything
docker compose up --build

# 3. Open the dashboard
# → http://localhost:8080

# 4. Generate attack events (in a new terminal)
docker compose run --rm simulator python generate_events.py --scenario brute_force
```

That's it. The simulator runs automatically in the background generating a mix
of normal and attack traffic.

---

## Quick Start (Local Python — No Docker)

**Requirements:** Python 3.10+

```bash
# Windows
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
bash run_local.sh          # Git Bash / WSL

# Mac/Linux
chmod +x run_local.sh
./run_local.sh
```

Then open **http://localhost:8080**.

---

## Generating Events Manually

```bash
# Docker
docker compose run --rm simulator python generate_events.py --scenario SCENARIO

# Local
python tools/generate_events.py --scenario SCENARIO
```

Available scenarios:

| Scenario | What it simulates |
|---|---|
| `brute_force` | 8 SSH failures from one IP → triggers BF001 |
| `cred_stuff` | Failures then success → triggers BF002 |
| `powershell` | Suspicious command lines → triggers PROC001/002 |
| `new_user` | Backdoor account creation → triggers USR001 |
| `dns_tunnel` | High-freq DNS + suspicious TLD → triggers DNS001/002 |
| `impossible_travel` | Same user, two distant locations → triggers TRAVEL001 |
| `web_scan` | 404/401 flood → triggers WEB001/002 |
| `normal` | Benign baseline events |
| `all` | Cycles through every attack scenario |

**Options:**

```bash
python tools/generate_events.py --scenario brute_force --count 15
python tools/generate_events.py --scenario all --loop --interval 5
```

---

## Ingest a Real auth.log

If you're on Linux (or WSL), you can point the ingestion service at your real
`/var/log/auth.log`:

```bash
# In docker-compose.yml, add to the ingestion service:
environment:
  - AUTH_LOG_PATH=/logs/auth.log
  - LOG_HOST=my-linux-host
volumes:
  - /var/log/auth.log:/logs/auth.log:ro
```

Or with the local runner:
```bash
AUTH_LOG_PATH=/var/log/auth.log LOG_HOST=$(hostname) ./run_local.sh
```

You can also replay the included sample:

```bash
# POST sample auth.log lines one by one
while IFS= read -r line; do
  curl -s -X POST http://localhost:8001/ingest \
    -H "Content-Type: application/json" \
    -d "{\"source\": \"linux-auth\", \"payload\": {\"line\": \"$line\", \"host\": \"demo-server\"}}"
done < sample_logs/auth.log
```

---

## Running Tests

```bash
# Install dev deps (pytest already in requirements.txt)
pip install pytest

# Run all tests
pytest tests/ -v

# Run just normalization tests
pytest tests/test_normalizers.py -v

# Run just detection tests
pytest tests/test_detection.py -v
```

---

## Project Layout

```
soc-lab/
├── docker-compose.yml          # Orchestrates all services
├── run_local.sh                # One-command local runner
├── requirements.txt
│
├── shared/
│   ├── schema.py               # NormalizedEvent + SQLite helpers
│   └── normalizers.py          # Source parsers (sim-endpoint, linux-auth)
│
├── services/
│   ├── ingestion/main.py       # FastAPI: POST /ingest, health check
│   ├── detection/main.py       # Polling detection engine
│   └── dashboard/
│       ├── main.py             # FastAPI: dashboard + investigation
│       └── templates/          # Jinja2 HTML templates
│
├── rules/
│   ├── brute_force.yml         # BF001, BF002, BF003
│   ├── suspicious_process.yml  # PROC001, PROC002, PROC003
│   └── network_and_identity.yml# DNS001, DNS002, USR001, WEB001, WEB002, TRAVEL001
│
├── tools/
│   └── generate_events.py      # Attack scenario simulator
│
├── tests/
│   ├── test_normalizers.py     # 18 normalization tests
│   └── test_detection.py       # 16 detection engine tests
│
├── sample_logs/auth.log        # Real-looking auth.log sample
├── db/                         # SQLite database lives here
│
├── README.md                   # This file
├── LAB_GUIDE.md                # Exercises and learning objectives
└── DESIGN.md                   # Architecture decisions
```

---

## Service Endpoints

| Service | URL | Purpose |
|---|---|---|
| Dashboard | http://localhost:8080 | Main UI |
| Investigate alert | http://localhost:8080/alert/{id} | Drill-down view |
| Ingestion health | http://localhost:8001/health | Source status |
| Ingest event | POST http://localhost:8001/ingest | Submit events |
| Registered sources | http://localhost:8001/sources | List parsers |

---

## Stopping

```bash
# Docker
docker compose down

# Local
Ctrl+C  (run_local.sh handles cleanup)
```

To wipe the database and start fresh:
```bash
rm db/soc.db
```
