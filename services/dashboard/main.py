"""
services/dashboard/main.py — SOC Dashboard (FastAPI + Jinja2)

Routes:
  GET  /                          — main dashboard
  GET  /alert/{id}                — investigation / triage view
  POST /alert/{id}/status         — update status + inline notes
  POST /alert/{id}/note           — append a note (alert_notes table)
  POST /alert/{id}/snooze         — snooze for N minutes
  POST /alert/{id}/unsnooze       — clear snooze
  GET  /suppressions              — suppression management page
  POST /suppressions/create       — create suppression from alert context
  POST /suppressions/delete       — delete a suppression by id
  GET  /events                    — HTMX partial: recent events
  GET  /api/stats                 — JSON stats for dashboard widgets
"""
from __future__ import annotations
import os, sys, json, logging
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, "/app")

import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from shared.schema import get_db, init_db, DB_PATH

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s [dashboard] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="SOC Lab - Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup():
    init_db(DB_PATH)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _q(sql: str, *params) -> list[dict]:
    con = get_db(DB_PATH)
    rows = [dict(r) for r in con.execute(sql, params).fetchall()]
    con.close()
    return rows


def _qone(sql: str, *params) -> dict | None:
    con = get_db(DB_PATH)
    r = con.execute(sql, params).fetchone()
    con.close()
    return dict(r) if r else None


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ── API: stats ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def stats():
    con = get_db(DB_PATH)
    now = _now()

    total_events = con.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    events_1h    = con.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE timestamp > datetime('now','-1 hour')"
    ).fetchone()[0]

    open_alerts = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE status='open' "
        "AND (snoozed_until IS NULL OR snoozed_until <= ?)", (now,)
    ).fetchone()[0]
    total_alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    snoozed_cnt  = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE snoozed_until IS NOT NULL AND snoozed_until > ?", (now,)
    ).fetchone()[0]

    by_severity = con.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts WHERE status='open' "
        "AND (snoozed_until IS NULL OR snoozed_until <= ?) GROUP BY severity", (now,)
    ).fetchall()

    by_source = con.execute(
        "SELECT source, COUNT(*) as cnt FROM normalized_events "
        "WHERE timestamp > datetime('now','-1 hour') GROUP BY source"
    ).fetchall()

    source_health = [dict(r) for r in con.execute("SELECT * FROM source_health").fetchall()]
    recent_rules  = [dict(r) for r in con.execute(
        "SELECT rule_name, COUNT(*) as cnt FROM rule_hits "
        "WHERE hit_at > datetime('now','-24 hours') GROUP BY rule_name ORDER BY cnt DESC LIMIT 5"
    ).fetchall()]

    active_suppressions = con.execute(
        "SELECT COUNT(*) FROM suppressions WHERE expires_at IS NULL OR expires_at > ?", (now,)
    ).fetchone()[0]

    con.close()
    return {
        "total_events":        total_events,
        "events_1h":           events_1h,
        "open_alerts":         open_alerts,
        "total_alerts":        total_alerts,
        "snoozed_cnt":         snoozed_cnt,
        "by_severity":         [dict(r) for r in by_severity],
        "by_source":           [dict(r) for r in by_source],
        "source_health":       source_health,
        "recent_rules":        recent_rules,
        "active_suppressions": active_suppressions,
    }


# ── Main dashboard ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, show_snoozed: int = 0):
    stats_data = await stats()
    now = _now()

    if show_snoozed:
        alerts = _q("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    else:
        alerts = _q(
            "SELECT * FROM alerts WHERE snoozed_until IS NULL OR snoozed_until <= ? "
            "ORDER BY created_at DESC LIMIT 50", now
        )

    events = _q("SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT 30")

    return templates.TemplateResponse("dashboard.html", {
        "request":      request,
        "stats":        stats_data,
        "alerts":       alerts,
        "events":       events,
        "show_snoozed": show_snoozed,
        "now":          now,
    })


# ── Alert investigation ───────────────────────────────────────────────────────

@app.get("/alert/{alert_id}", response_class=HTMLResponse)
async def investigate(request: Request, alert_id: str):
    alert = _qone("SELECT * FROM alerts WHERE alert_id=?", alert_id)
    if not alert:
        return HTMLResponse("<h2>Alert not found</h2>", status_code=404)

    event = _qone("SELECT * FROM normalized_events WHERE event_id=?", alert["event_id"])
    if event and isinstance(event.get("fields"), str):
        try:
            event["fields"] = json.loads(event["fields"])
        except Exception:
            pass

    rule_hits = _q("SELECT * FROM rule_hits WHERE event_id=?", alert["event_id"])
    for rh in rule_hits:
        try:
            rh["matched_on"] = json.loads(rh["matched_on"])
        except Exception:
            pass

    related = []
    if event:
        related = _q(
            "SELECT * FROM normalized_events WHERE host=? AND event_id!=? "
            "AND timestamp BETWEEN datetime(?,'- 5 minutes') AND datetime(?,'+ 5 minutes') "
            "ORDER BY timestamp DESC LIMIT 10",
            event["host"], event["event_id"], event["timestamp"], event["timestamp"]
        )

    notes_history = _q(
        "SELECT * FROM alert_notes WHERE alert_id=? ORDER BY created_at ASC", alert_id
    )

    now = _now()
    active_suppressions = _q(
        "SELECT * FROM suppressions WHERE rule_id=? "
        "AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC",
        alert["rule_id"], now
    )

    is_snoozed = bool(alert.get("snoozed_until") and alert["snoozed_until"] > now)

    return templates.TemplateResponse("investigate.html", {
        "request":             request,
        "alert":               alert,
        "event":               event,
        "rule_hits":           rule_hits,
        "related":             related,
        "notes_history":       notes_history,
        "active_suppressions": active_suppressions,
        "is_snoozed":          is_snoozed,
        "now":                 now,
    })


# ── Triage: status ────────────────────────────────────────────────────────────

@app.post("/alert/{alert_id}/status")
async def update_status(alert_id: str, status: str = Form(...), notes: str = Form("")):
    con = get_db(DB_PATH)
    con.execute("UPDATE alerts SET status=?, notes=? WHERE alert_id=?",
                (status, notes, alert_id))
    con.commit()
    con.close()
    return JSONResponse({"ok": True, "status": status})


# ── Notes (append-only) ───────────────────────────────────────────────────────

@app.post("/alert/{alert_id}/note")
async def add_note(alert_id: str, note: str = Form(...)):
    if not note.strip():
        return JSONResponse({"ok": False, "error": "empty note"}, status_code=400)
    now = _now()
    con = get_db(DB_PATH)
    con.execute(
        "INSERT INTO alert_notes (alert_id, created_at, note) VALUES (?,?,?)",
        (alert_id, now, note.strip())
    )
    con.commit()
    con.close()
    return JSONResponse({"ok": True, "created_at": now})


# ── Snooze ────────────────────────────────────────────────────────────────────

@app.post("/alert/{alert_id}/snooze")
async def snooze_alert(alert_id: str, minutes: int = Form(...)):
    until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat() + "Z"
    con = get_db(DB_PATH)
    con.execute("UPDATE alerts SET snoozed_until=? WHERE alert_id=?", (until, alert_id))
    con.commit()
    con.close()
    log.info("Snoozed alert %s until %s", alert_id[:8], until)
    return JSONResponse({"ok": True, "snoozed_until": until})


@app.post("/alert/{alert_id}/unsnooze")
async def unsnooze_alert(alert_id: str):
    con = get_db(DB_PATH)
    con.execute("UPDATE alerts SET snoozed_until=NULL WHERE alert_id=?", (alert_id,))
    con.commit()
    con.close()
    return JSONResponse({"ok": True})


# ── Suppressions ──────────────────────────────────────────────────────────────

DURATION_MAP = {
    "1h":        60,
    "24h":       60 * 24,
    "7d":        60 * 24 * 7,
    "permanent": None,
}


@app.post("/suppressions/create")
async def create_suppression(
    rule_id:     str = Form(...),
    rule_name:   str = Form(...),
    scope:       str = Form(...),
    match_value: str = Form(""),
    duration:    str = Form("permanent"),
    redirect_to: str = Form(""),
):
    if scope not in ("global", "host", "user"):
        return JSONResponse({"ok": False, "error": "invalid scope"}, status_code=400)

    minutes = DURATION_MAP.get(duration)
    expires_at = None
    if minutes is not None:
        expires_at = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat() + "Z"

    mv = match_value.strip() if scope != "global" else None

    con = get_db(DB_PATH)
    con.execute(
        "INSERT INTO suppressions (rule_id, rule_name, scope, match_value, created_at, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (rule_id, rule_name, scope, mv, _now(), expires_at)
    )
    con.commit()
    con.close()
    log.info("Suppression created: rule=%s scope=%s match=%s expires=%s",
             rule_id, scope, mv, expires_at)

    if redirect_to:
        return RedirectResponse(redirect_to, status_code=303)
    return JSONResponse({"ok": True})


@app.post("/suppressions/delete")
async def delete_suppression(suppression_id: int = Form(...)):
    con = get_db(DB_PATH)
    con.execute("DELETE FROM suppressions WHERE id=?", (suppression_id,))
    con.commit()
    con.close()
    return RedirectResponse("/suppressions", status_code=303)


@app.get("/suppressions", response_class=HTMLResponse)
async def suppressions_page(request: Request):
    now = _now()
    all_suppressions = _q("SELECT * FROM suppressions ORDER BY created_at DESC")
    for s in all_suppressions:
        s["is_active"] = s["expires_at"] is None or s["expires_at"] > now
    return templates.TemplateResponse("suppressions.html", {
        "request":      request,
        "suppressions": all_suppressions,
        "now":          now,
        "active_count": sum(1 for s in all_suppressions if s["is_active"]),
    })


# ── Events partial ────────────────────────────────────────────────────────────

@app.get("/events", response_class=HTMLResponse)
async def events_partial(request: Request, limit: int = 50):
    rows = _q("SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT ?", limit)
    return templates.TemplateResponse("partials/events.html", {"request": request, "events": rows})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
