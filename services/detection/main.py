"""
services/detection/main.py — Detection engine + rule-reload HTTP endpoint

Runs two things in the same process:
  1. Poll loop  — reads new normalized_events every POLL_INTERVAL seconds,
                  evaluates rules, writes alerts.
  2. HTTP server (port 8002) — exposes:
       POST /reload-rules   reload YAML files without restarting the container
       GET  /rules          list currently loaded rules (id, name, severity)
       GET  /health         liveness check

Rule state is stored in a module-level RuleSet protected by a threading.Lock,
so the HTTP handler and the poll loop can never read a half-written rule list.
"""
from __future__ import annotations
import os, sys, json, re, time, logging, uuid, threading
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, "/app")

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from shared.schema import get_db, init_db, DB_PATH, NormalizedEvent

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s [detection] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

RULES_DIR     = Path(os.environ.get("RULES_DIR", "/app/rules"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECS", "5"))
HTTP_PORT     = int(os.environ.get("DETECTION_HTTP_PORT", "8002"))

# Deduplication window: only one alert per rule+host within this many seconds
DEDUP_WINDOW_SECS = int(os.environ.get("DEDUP_WINDOW_SECS", "3600"))


# ── Thread-safe rule store ────────────────────────────────────────────────────

class RuleSet:
    """Holds the loaded rule list behind a RW lock."""
    def __init__(self):
        self._lock  = threading.Lock()
        self._rules: list[dict] = []

    def load(self) -> int:
        rules = _load_rules_from_disk()
        with self._lock:
            self._rules = rules
        return len(rules)

    def get(self) -> list[dict]:
        with self._lock:
            return list(self._rules)   # shallow copy — safe to iterate


_ruleset = RuleSet()


# ── Rule loading ──────────────────────────────────────────────────────────────

def _load_rules_from_disk() -> list[dict]:
    rules = []
    for p in sorted(RULES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(p.read_text())
            if isinstance(data, list):
                rules.extend(data)
            else:
                rules.append(data)
            log.debug("Loaded rule file: %s", p.name)
        except Exception as exc:
            log.error("Failed to load %s: %s", p, exc)
    log.info("Loaded %d rules from %s", len(rules), RULES_DIR)
    return rules

# Keep old name for test compatibility
def load_rules() -> list[dict]:
    return _load_rules_from_disk()


# ── Field extraction ──────────────────────────────────────────────────────────

def _get_field(event: NormalizedEvent, field_path: str):
    if field_path.startswith("fields."):
        key = field_path[len("fields."):]
        return event.fields.get(key)
    return getattr(event, field_path, None)


# ── Single-event rule matching ────────────────────────────────────────────────

def _match_single(event: NormalizedEvent, rule: dict) -> tuple[bool, list[str]]:
    match_block = rule.get("match", {})
    if not match_block:
        return False, []

    matched_on = []
    for field_path, expected in match_block.items():
        actual = _get_field(event, field_path)
        if actual is None:
            return False, []

        if isinstance(expected, list):
            if str(actual) not in [str(v) for v in expected]:
                return False, []
            matched_on.append(f"{field_path} in {expected}")

        elif isinstance(expected, str) and expected.startswith("~"):
            pattern = expected[1:]
            if not re.search(pattern, str(actual), re.IGNORECASE):
                return False, []
            matched_on.append(f"{field_path} =~ {pattern!r}")

        else:
            if str(actual).lower() != str(expected).lower():
                return False, []
            matched_on.append(f"{field_path} == {expected!r}")

    return True, matched_on


# ── Time-window rule matching ─────────────────────────────────────────────────

def _match_timewindow(event: NormalizedEvent, rule: dict, con) -> tuple[bool, list[str]]:
    w = rule.get("window")
    if not w:
        return False, []

    group_field = w.get("field")
    req_count   = int(w.get("count", 3))
    seconds     = int(w.get("seconds", 60))
    req_etype   = w.get("event_type", event.event_type)

    if event.event_type != req_etype:
        return False, []

    group_val = _get_field(event, group_field) or _get_field(event, "fields." + group_field)
    if not group_val:
        return False, []

    since = (datetime.utcnow() - timedelta(seconds=seconds)).isoformat() + "Z"

    rows = con.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE event_type=? AND timestamp > ?",
        (req_etype, since)
    ).fetchone()[0]

    if group_field.startswith("fields."):
        jkey = group_field[len("fields."):]
        rows = con.execute(
            "SELECT COUNT(*) FROM normalized_events WHERE event_type=? AND timestamp > ? "
            "AND json_extract(fields, ?) = ?",
            (req_etype, since, f"$.{jkey}", group_val)
        ).fetchone()[0]

    if rows >= req_count:
        return True, [f"{group_field}={group_val} had {rows} {req_etype} events in {seconds}s"]

    return False, []


# ── Credential-stuffing pattern ───────────────────────────────────────────────

def _match_fail_then_success(event: NormalizedEvent, rule: dict, con) -> tuple[bool, list[str]]:
    if rule.get("type") != "fail_then_success":
        return False, []
    if event.event_type != "auth_success":
        return False, []

    src_ip  = event.fields.get("src_ip")
    seconds = int(rule.get("window_seconds", 300))
    thresh  = int(rule.get("fail_threshold", 3))

    if not src_ip:
        return False, []

    since = (datetime.utcnow() - timedelta(seconds=seconds)).isoformat() + "Z"
    fail_count = con.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE event_type='auth_fail' AND timestamp > ? "
        "AND json_extract(fields,'$.src_ip') = ?",
        (since, src_ip)
    ).fetchone()[0]

    if fail_count >= thresh:
        return True, [f"{fail_count} auth_fail from {src_ip} in {seconds}s before success"]

    return False, []


# ── Suppression check ─────────────────────────────────────────────────────────

def _is_suppressed(con, rule_id: str, host: str, user: str | None) -> bool:
    now = datetime.utcnow().isoformat() + "Z"
    row = con.execute("""
        SELECT id FROM suppressions
        WHERE rule_id = ?
          AND (expires_at IS NULL OR expires_at > ?)
          AND (
            scope = 'global'
            OR (scope = 'host' AND match_value = ?)
            OR (scope = 'user' AND match_value = ?)
          )
        LIMIT 1
    """, (rule_id, now, host, user or "")).fetchone()

    if row:
        con.execute(
            "UPDATE suppressions SET suppressed_hits = suppressed_hits + 1 WHERE id = ?",
            (row[0],)
        )
        con.commit()
        return True
    return False


# ── Alert deduplication ───────────────────────────────────────────────────────

def _find_open_dedup_alert(con, rule_id: str, host: str) -> dict | None:
    """
    Look for an existing open (non-snoozed) alert for the same rule+host
    created within DEDUP_WINDOW_SECS.  Returns the alert row dict or None.
    """
    since = (datetime.utcnow() - timedelta(seconds=DEDUP_WINDOW_SECS)).isoformat() + "Z"
    now   = datetime.utcnow().isoformat() + "Z"
    row = con.execute("""
        SELECT alert_id, hit_count FROM alerts
        WHERE  rule_id = ?
          AND  host    = ?
          AND  status  = 'open'
          AND  created_at >= ?
          AND  (snoozed_until IS NULL OR snoozed_until <= ?)
        ORDER BY created_at DESC
        LIMIT 1
    """, (rule_id, host, since, now)).fetchone()
    return dict(row) if row else None


def _increment_dedup_alert(con, alert_id: str, event_id: str,
                            matched_on: list[str], rule: dict) -> None:
    """Bump hit_count + last_hit_at on an existing deduplicated alert."""
    now = datetime.utcnow().isoformat() + "Z"
    con.execute("""
        UPDATE alerts
        SET hit_count  = hit_count + 1,
            last_hit_at = ?
        WHERE alert_id = ?
    """, (now, alert_id))
    # Still record the individual rule hit for audit trail
    con.execute("""
        INSERT INTO rule_hits (hit_at, rule_id, rule_name, event_id, matched_on)
        VALUES (?,?,?,?,?)
    """, (now, rule["id"], rule["name"], event_id, json.dumps(matched_on + ["[DEDUP]"])))
    con.commit()
    log.info("DEDUP   rule=%s  alert=%s  hit_count++", rule["name"], alert_id[:8])


# ── Alert writer ──────────────────────────────────────────────────────────────

def _already_alerted(con, rule_id: str, event_id: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM rule_hits WHERE rule_id=? AND event_id=?",
        (rule_id, event_id)
    ).fetchone()
    return row is not None


def _write_alert(con, rule: dict, event: NormalizedEvent, matched_on: list[str]):
    """
    Write a new alert, or if an open dedup-window alert already exists for
    this rule+host, increment its counter instead.
    """
    # Deduplication check
    existing = _find_open_dedup_alert(con, rule["id"], event.host)
    if existing:
        _increment_dedup_alert(con, existing["alert_id"], event.event_id,
                               matched_on, rule)
        return

    # New alert
    alert_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + "Z"

    attack = rule.get("attack", {})

    con.execute("""
        INSERT OR IGNORE INTO alerts
            (alert_id, created_at, rule_id, rule_name, severity,
             event_id, host, user, summary, status, hit_count, last_hit_at,
             attack_technique_id, attack_technique_name, attack_tactic)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        alert_id, now,
        rule["id"], rule["name"],
        rule.get("severity", "medium"),
        event.event_id, event.host, event.user,
        f"[{rule['name']}] {event.summary}",
        "open",
        1, now,
        attack.get("technique_id"),
        attack.get("technique_name"),
        attack.get("tactic"),
    ))

    con.execute("""
        INSERT INTO rule_hits (hit_at, rule_id, rule_name, event_id, matched_on)
        VALUES (?,?,?,?,?)
    """, (now, rule["id"], rule["name"], event.event_id, json.dumps(matched_on)))

    con.commit()
    log.warning("ALERT  rule=%s  event=%s  host=%s  user=%s",
                rule["name"], event.event_id[:8], event.host, event.user)


# ── Evaluate one event against all rules ─────────────────────────────────────

def _evaluate(con, rules: list[dict], event: NormalizedEvent):
    for rule in rules:
        if _already_alerted(con, rule["id"], event.event_id):
            continue

        matched, matched_on = _match_single(event, rule)
        if not matched:
            matched, matched_on = _match_timewindow(event, rule, con)
        if not matched:
            matched, matched_on = _match_fail_then_success(event, rule, con)

        if matched:
            if _is_suppressed(con, rule["id"], event.host, event.user):
                log.info("SUPPRESSED  rule=%s  host=%s  user=%s",
                         rule["id"], event.host, event.user)
                now = datetime.utcnow().isoformat() + "Z"
                con.execute(
                    "INSERT INTO rule_hits (hit_at, rule_id, rule_name, event_id, matched_on) "
                    "VALUES (?,?,?,?,?)",
                    (now, rule["id"], rule["name"], event.event_id,
                     json.dumps(matched_on + ["[SUPPRESSED]"]))
                )
                con.commit()
                continue
            _write_alert(con, rule, event, matched_on)


# ── Main detection loop ───────────────────────────────────────────────────────

def run_detection():
    init_db(DB_PATH)
    count = _ruleset.load()
    log.info("Detection engine started with %d rules. Polling every %ds …",
             count, POLL_INTERVAL)

    last_seen_rowid = 0
    con = get_db(DB_PATH)
    row = con.execute("SELECT MAX(rowid) FROM normalized_events").fetchone()
    if row and row[0]:
        last_seen_rowid = row[0]
    con.close()

    while True:
        try:
            con = get_db(DB_PATH)
            new_rows = con.execute(
                "SELECT rowid, * FROM normalized_events WHERE rowid > ? ORDER BY rowid",
                (last_seen_rowid,)
            ).fetchall()

            rules = _ruleset.get()
            for row in new_rows:
                last_seen_rowid = row["rowid"]
                event = NormalizedEvent.from_dict(dict(row))
                _evaluate(con, rules, event)

            con.close()
        except Exception as exc:
            log.error("Detection loop error: %s", exc, exc_info=True)

        time.sleep(POLL_INTERVAL)


# ── HTTP control server ───────────────────────────────────────────────────────

http_app = FastAPI(title="SOC Lab – Detection Control")
http_app.add_middleware(CORSMiddleware, allow_origins=["*"],
                        allow_methods=["*"], allow_headers=["*"])


@http_app.post("/reload-rules")
async def reload_rules():
    """
    Hot-reload all YAML rule files from disk without restarting the container.
    The poll loop picks up the new rule list on its very next iteration.
    """
    try:
        count = _ruleset.load()
        rules = _ruleset.get()
        log.info("Rules reloaded via HTTP: %d rules", count)
        return {
            "ok":    True,
            "count": count,
            "rules": [{"id": r["id"], "name": r["name"],
                       "severity": r.get("severity","?")} for r in rules],
        }
    except Exception as exc:
        log.error("Rule reload failed: %s", exc)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@http_app.get("/rules")
async def list_rules():
    rules = _ruleset.get()
    return {
        "count": len(rules),
        "rules": [{"id": r["id"], "name": r["name"],
                   "severity": r.get("severity", "?"),
                   "tags": r.get("tags", [])} for r in rules],
    }


@http_app.get("/health")
async def health():
    return {"status": "ok", "rules_loaded": len(_ruleset.get())}


def _start_http_server():
    """Run the FastAPI control plane in a daemon thread."""
    config = uvicorn.Config(http_app, host="0.0.0.0", port=HTTP_PORT,
                            log_level="warning", loop="asyncio")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True, name="detection-http")
    t.start()
    log.info("Detection control server started on port %d", HTTP_PORT)


if __name__ == "__main__":
    _start_http_server()
    run_detection()
