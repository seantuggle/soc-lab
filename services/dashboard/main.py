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
  GET  /attack-coverage           — MITRE ATT&CK coverage matrix
  GET  /host/{hostname}           — host timeline view
  GET  /api/hosts                 — JSON list of known hosts
  GET  /alerts/export             — download alerts as CSV or JSON
  GET  /alerts/export-ui          — full export page with filters + preview
  GET  /api/alerts/count          — JSON count preview for export page
  GET  /threat-intel              — threat intelligence feed manager
  POST /threat-intel/feeds/add    — add a new TI feed
  POST /threat-intel/feeds/refresh — fetch/refresh a feed now
  POST /threat-intel/feeds/delete — remove a feed and its IOCs
  POST /threat-intel/iocs/add     — manually add an IOC
  POST /threat-intel/iocs/delete  — remove an IOC
  GET  /events                    — HTMX partial: recent events
  GET  /api/stats                 — JSON stats for dashboard widgets
"""
from __future__ import annotations
import os, sys, json, logging, csv, io
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, "/app")

import yaml
import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
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


# ── Rule metadata cache ───────────────────────────────────────────────────────

_rule_cache: dict[str, dict] = {}   # rule_id → full rule dict

def _get_rule_meta(rule_id: str) -> dict:
    """
    Return the full rule dict for a given rule_id, loaded from YAML.
    Results are cached in-process. Returns {} if rule not found.
    """
    if rule_id in _rule_cache:
        return _rule_cache[rule_id]

    rules_dir = Path(os.environ.get("RULES_DIR", "/app/rules"))
    for p in rules_dir.glob("*.yml"):
        try:
            data = yaml.safe_load(p.read_text())
            if not isinstance(data, list):
                data = [data]
            for rule in data:
                if isinstance(rule, dict):
                    _rule_cache[rule.get("id", "")] = rule
        except Exception:
            pass

    return _rule_cache.get(rule_id, {})


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
    rule_meta  = _get_rule_meta(alert["rule_id"])

    # TI context for the triggering event's src_ip
    ti_data = {}
    if event and isinstance(event.get("fields"), dict):
        src_ip = event["fields"].get("src_ip")
        if src_ip and not event["fields"].get("src_ip_internal"):
            from shared.threat_intel import get_ip_reputation, lookup_ioc
            ti_data["ip_rep"] = get_ip_reputation(str(src_ip))
        dns_q = event["fields"].get("dns_query")
        if dns_q:
            from shared.threat_intel import get_domain_reputation
            ti_data["domain_rep"] = get_domain_reputation(str(dns_q))

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
        "rule_meta":           rule_meta,
        "ti_data":             ti_data,
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


# ── ATT&CK Coverage Matrix ────────────────────────────────────────────────────

# The 14 ATT&CK tactics in kill-chain order
ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _load_all_rules() -> list[dict]:
    """Load every rule from every YAML file in RULES_DIR."""
    rules_dir = Path(os.environ.get("RULES_DIR", "/app/rules"))
    all_rules = []
    for p in sorted(rules_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(p.read_text())
            if not isinstance(data, list):
                data = [data]
            for rule in data:
                if isinstance(rule, dict):
                    all_rules.append(rule)
        except Exception as exc:
            log.warning("Could not load %s: %s", p, exc)
    return all_rules


@app.get("/attack-coverage", response_class=HTMLResponse)
async def attack_coverage(request: Request):
    rules = _load_all_rules()

    # Pull alert counts per rule from DB (last 30 days)
    alert_rows = _q(
        "SELECT rule_id, COUNT(*) as cnt, MAX(created_at) as last_seen "
        "FROM alerts WHERE created_at > datetime('now','-30 days') "
        "GROUP BY rule_id"
    )
    alert_counts = {r["rule_id"]: r for r in alert_rows}

    # Build per-tactic buckets
    # tactic_map: tactic → list of technique dicts
    tactic_map: dict[str, list[dict]] = {t: [] for t in ATTACK_TACTICS}
    uncovered_tactics: set[str] = set(ATTACK_TACTICS)

    rules_with_attack = 0
    rules_without_attack = []

    for rule in rules:
        atk = rule.get("attack")
        if not atk:
            rules_without_attack.append(rule)
            continue

        rules_with_attack += 1
        tactic = atk.get("tactic", "Unknown")
        counts = alert_counts.get(rule["id"], {})

        cell = {
            "rule_id":        rule["id"],
            "rule_name":      rule["name"],
            "technique_id":   atk.get("technique_id", ""),
            "technique_name": atk.get("technique_name", ""),
            "tactic":         tactic,
            "url":            atk.get("url", ""),
            "severity":       rule.get("severity", "info"),
            "alert_count":    counts.get("cnt", 0),
            "last_seen":      counts.get("last_seen", None),
            "tags":           rule.get("tags", []),
        }

        if tactic in tactic_map:
            tactic_map[tactic].append(cell)
            uncovered_tactics.discard(tactic)
        else:
            # Unknown tactic — don't silently drop it
            if tactic not in tactic_map:
                tactic_map[tactic] = []
            tactic_map[tactic].append(cell)

    # Coverage stats
    covered_tactics   = len(ATTACK_TACTICS) - len(uncovered_tactics)
    total_alert_count = sum(r.get("cnt", 0) for r in alert_rows)
    total_techniques  = rules_with_attack

    return templates.TemplateResponse("attack_coverage.html", {
        "request":             request,
        "tactic_map":          tactic_map,
        "tactics":             ATTACK_TACTICS,
        "uncovered_tactics":   uncovered_tactics,
        "covered_tactics":     covered_tactics,
        "total_tactics":       len(ATTACK_TACTICS),
        "total_techniques":    total_techniques,
        "total_alert_count":   total_alert_count,
        "rules_without_attack": rules_without_attack,
    })


# ── Host Timeline ─────────────────────────────────────────────────────────────

@app.get("/api/hosts")
async def list_hosts():
    """Return all known hosts sorted by most recent activity."""
    rows = _q(
        "SELECT host, COUNT(*) as event_count, MAX(timestamp) as last_seen "
        "FROM normalized_events GROUP BY host ORDER BY last_seen DESC"
    )
    return {"hosts": rows}


@app.get("/host/{hostname}", response_class=HTMLResponse)
async def host_timeline(
    request: Request,
    hostname: str,
    days: int = 7,
    event_type: str = "",
):
    since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"

    # All events for this host in the window
    if event_type:
        events = _q(
            "SELECT * FROM normalized_events WHERE host=? AND timestamp >= ? "
            "AND event_type=? ORDER BY timestamp ASC",
            hostname, since, event_type,
        )
    else:
        events = _q(
            "SELECT * FROM normalized_events WHERE host=? AND timestamp >= ? "
            "ORDER BY timestamp ASC",
            hostname, since,
        )

    # Parse fields JSON for each event
    for e in events:
        if isinstance(e.get("fields"), str):
            try:
                e["fields"] = json.loads(e["fields"])
            except Exception:
                e["fields"] = {}

    # All alerts for this host in the window
    alerts = _q(
        "SELECT * FROM alerts WHERE host=? AND created_at >= ? "
        "ORDER BY created_at ASC",
        hostname, since,
    )

    # Merge into a single timeline list
    # Each entry: {kind: "event"|"alert", ts: str, data: dict}
    timeline = []
    for e in events:
        timeline.append({
            "kind": "event",
            "ts":   e["timestamp"],
            "data": e,
        })
    for a in alerts:
        timeline.append({
            "kind": "alert",
            "ts":   a["created_at"],
            "data": a,
        })
    timeline.sort(key=lambda x: x["ts"])

    # Distinct event types for the filter dropdown
    event_types = _q(
        "SELECT DISTINCT event_type FROM normalized_events WHERE host=? "
        "AND timestamp >= ? ORDER BY event_type",
        hostname, since,
    )

    # Host summary stats
    stats = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "open_alerts":  sum(1 for a in alerts if a["status"] == "open"),
        "first_seen":   timeline[0]["ts"][:19].replace("T", " ") if timeline else "—",
        "last_seen":    timeline[-1]["ts"][:19].replace("T", " ") if timeline else "—",
    }

    # All hosts for the host picker
    all_hosts = _q(
        "SELECT host, MAX(timestamp) as last_seen FROM normalized_events "
        "GROUP BY host ORDER BY last_seen DESC LIMIT 30"
    )

    return templates.TemplateResponse("host_timeline.html", {
        "request":     request,
        "hostname":    hostname,
        "timeline":    timeline,
        "stats":       stats,
        "days":        days,
        "event_type":  event_type,
        "event_types": [r["event_type"] for r in event_types],
        "all_hosts":   all_hosts,
    })


# ── Alert Export ──────────────────────────────────────────────────────────────

# Columns included in every export
EXPORT_COLUMNS = [
    "alert_id", "created_at", "rule_id", "rule_name", "severity",
    "host", "user", "summary", "status", "hit_count", "last_hit_at",
    "attack_technique_id", "attack_technique_name", "attack_tactic",
    "snoozed_until", "notes",
]


@app.get("/alerts/export")
async def export_alerts(
    fmt:          str = "csv",   # "csv" or "json"
    severity:     str = "",
    status:       str = "",
    host:         str = "",
    rule:         str = "",
    show_snoozed: int = 0,
    days:         int = 0,       # 0 = all time, otherwise restrict to last N days
):
    """
    Export alerts as CSV or JSON — no row limit.
    Called by both the dashboard quick-export buttons and the export UI page.
    """
    now = _now()

    clauses, params = [], []

    # Date window
    if days > 0:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        clauses.append("created_at >= ?")
        params.append(since)

    if not show_snoozed:
        clauses.append("(snoozed_until IS NULL OR snoozed_until <= ?)")
        params.append(now)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if host:
        clauses.append("LOWER(host) LIKE ?")
        params.append(f"%{host.lower()}%")
    if rule:
        clauses.append("LOWER(rule_name) LIKE ?")
        params.append(f"%{rule.lower()}%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql   = f"SELECT * FROM alerts {where} ORDER BY created_at DESC"
    rows  = _q(sql, *params)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ── CSV ───────────────────────────────────────────────────────────
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=EXPORT_COLUMNS,
            extrasaction="ignore", lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") or "" for col in EXPORT_COLUMNS})
        buf.seek(0)
        filename = f"soc_alerts_{ts}.csv"
        return StreamingResponse(
            iter([buf.getvalue()]), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # ── JSON ──────────────────────────────────────────────────────────
    else:
        export = {
            "exported_at": now,
            "filter": {
                "days":         days or "all",
                "severity":     severity or "all",
                "status":       status   or "all",
                "host":         host     or "all",
                "rule":         rule     or "all",
                "show_snoozed": bool(show_snoozed),
            },
            "count":  len(rows),
            "alerts": [{col: row.get(col) for col in EXPORT_COLUMNS} for row in rows],
        }
        content  = json.dumps(export, indent=2, default=str)
        filename = f"soc_alerts_{ts}.json"
        return StreamingResponse(
            iter([content]), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/api/alerts/count")
async def alerts_count(
    severity:     str = "",
    status:       str = "",
    host:         str = "",
    rule:         str = "",
    show_snoozed: int = 0,
    days:         int = 0,
):
    """Live count used by the export UI preview — fast, no data transfer."""
    now = _now()
    clauses, params = [], []

    if days > 0:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        clauses.append("created_at >= ?")
        params.append(since)
    if not show_snoozed:
        clauses.append("(snoozed_until IS NULL OR snoozed_until <= ?)")
        params.append(now)
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    if status:
        clauses.append("status = ?");   params.append(status)
    if host:
        clauses.append("LOWER(host) LIKE ?"); params.append(f"%{host.lower()}%")
    if rule:
        clauses.append("LOWER(rule_name) LIKE ?"); params.append(f"%{rule.lower()}%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    con   = get_db(DB_PATH)
    count = con.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
    con.close()
    return {"count": count}


@app.get("/alerts/export-ui", response_class=HTMLResponse)
async def export_ui(request: Request):
    """Dedicated export page — no row limit, full filter control, live preview."""
    # Populate host dropdown from DB
    hosts = _q(
        "SELECT DISTINCT host FROM alerts ORDER BY host"
    )
    # Populate rule dropdown
    rules = _q(
        "SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name"
    )
    # Total alert count for context
    total = _qone("SELECT COUNT(*) as cnt FROM alerts")
    oldest = _qone("SELECT MIN(created_at) as ts FROM alerts")

    return templates.TemplateResponse("export_ui.html", {
        "request": request,
        "hosts":   [r["host"] for r in hosts],
        "rules":   [r["rule_name"] for r in rules],
        "total":   total["cnt"] if total else 0,
        "oldest":  oldest["ts"][:10] if oldest and oldest["ts"] else "—",
    })


# ── Threat Intelligence ───────────────────────────────────────────────────────

@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request):
    from shared.threat_intel import seed_builtin_iocs, seed_builtin_feeds
    seed_builtin_iocs()
    seed_builtin_feeds()

    feeds = _q("SELECT * FROM ti_feeds ORDER BY added_at DESC")
    for f in feeds:
        if isinstance(f.get("tags"), str):
            try:    f["tags"] = json.loads(f["tags"])
            except: f["tags"] = []

    iocs = _q(
        "SELECT * FROM iocs WHERE feed_id IS NULL ORDER BY added_at DESC LIMIT 200"
    )
    for i in iocs:
        if isinstance(i.get("tags"), str):
            try:    i["tags"] = json.loads(i["tags"])
            except: i["tags"] = []

    con = get_db(DB_PATH)
    total_iocs   = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    mal_iocs     = con.execute("SELECT COUNT(*) FROM iocs WHERE verdict='malicious'").fetchone()[0]
    cache_count  = con.execute("SELECT COUNT(*) FROM ip_reputation_cache").fetchone()[0]
    feed_iocs    = con.execute("SELECT COUNT(*) FROM iocs WHERE feed_id IS NOT NULL").fetchone()[0]
    con.close()

    api_status = {
        "abuseipdb":  bool(os.environ.get("ABUSEIPDB_API_KEY")),
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
    }

    return templates.TemplateResponse("threat_intel.html", {
        "request":     request,
        "feeds":       feeds,
        "iocs":        iocs,
        "total_iocs":  total_iocs,
        "mal_iocs":    mal_iocs,
        "cache_count": cache_count,
        "feed_iocs":   feed_iocs,
        "api_status":  api_status,
    })


@app.post("/threat-intel/feeds/add")
async def add_feed(
    name:      str = Form(...),
    url:       str = Form(...),
    feed_type: str = Form("ip"),
    tags:      str = Form(""),
    verdict:   str = Form("malicious"),
    score:     int = Form(75),
):
    import json as _json
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    con = get_db(DB_PATH)
    try:
        con.execute("""
            INSERT INTO ti_feeds (name, url, feed_type, format, tags, verdict, score,
                                  description, enabled, added_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (name, url, feed_type, "plain", _json.dumps(tag_list),
              verdict, score, "", 1, _now()))
        con.commit()
    except Exception as exc:
        log.warning("add_feed error: %s", exc)
    con.close()
    return RedirectResponse("/threat-intel", status_code=303)


@app.post("/threat-intel/feeds/refresh")
async def refresh_feed(feed_id: int = Form(...)):
    from shared.threat_intel import fetch_feed
    feed_row = _qone("SELECT * FROM ti_feeds WHERE id=?", feed_id)
    if not feed_row:
        return RedirectResponse("/threat-intel", status_code=303)

    if isinstance(feed_row.get("tags"), str):
        try:    feed_row["tags"] = json.loads(feed_row["tags"])
        except: feed_row["tags"] = []

    feed_row["feed_id"] = feed_id
    count, err = fetch_feed(feed_row)

    con = get_db(DB_PATH)
    con.execute(
        "UPDATE ti_feeds SET last_fetched=?, last_count=?, last_error=? WHERE id=?",
        (_now(), count, err or None, feed_id)
    )
    con.commit()
    con.close()
    log.info("Feed %d refreshed: %d IOCs, err=%s", feed_id, count, err or "none")
    return RedirectResponse("/threat-intel", status_code=303)


@app.post("/threat-intel/feeds/delete")
async def delete_feed(feed_id: int = Form(...)):
    con = get_db(DB_PATH)
    con.execute("DELETE FROM iocs WHERE feed_id=?", (feed_id,))
    con.execute("DELETE FROM ti_feeds WHERE id=?", (feed_id,))
    con.commit()
    con.close()
    return RedirectResponse("/threat-intel", status_code=303)


@app.post("/threat-intel/iocs/add")
async def add_ioc_manual(
    ioc_type:    str = Form(...),
    value:       str = Form(...),
    verdict:     str = Form("malicious"),
    score:       int = Form(75),
    tags:        str = Form(""),
    actor:       str = Form(""),
    description: str = Form(""),
):
    from shared.threat_intel import add_ioc
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    add_ioc(
        ioc_type=ioc_type, value=value, verdict=verdict,
        score=score, tags=tag_list, source="manual",
        description=description, actor=actor,
    )
    return RedirectResponse("/threat-intel", status_code=303)


@app.post("/threat-intel/iocs/delete")
async def delete_ioc(ioc_id: int = Form(...)):
    con = get_db(DB_PATH)
    con.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
    con.commit()
    con.close()
    return RedirectResponse("/threat-intel", status_code=303)


# ── Events partial ────────────────────────────────────────────────────────────

@app.get("/events", response_class=HTMLResponse)
async def events_partial(request: Request, limit: int = 50):
    rows = _q("SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT ?", limit)
    return templates.TemplateResponse("partials/events.html", {"request": request, "events": rows})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
