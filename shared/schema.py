"""
shared/schema.py  — Normalized event schema + SQLite helpers
Every service imports from this module.
"""
from __future__ import annotations
import sqlite3, uuid, json, os
from datetime import datetime
from typing import Optional, Any

DB_PATH = os.environ.get("DB_PATH", "./db/soc.db")

# ── Normalized Event Schema ───────────────────────────────────────────────────

class NormalizedEvent:
    """
    One canonical event flowing through the pipeline.
    All parsers must return this shape.
    """
    def __init__(
        self,
        source: str,
        host: str,
        event_type: str,
        summary: str,
        raw: Any,
        severity: str = "info",
        user: Optional[str] = None,
        fields: Optional[dict] = None,
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ):
        self.event_id   = event_id or str(uuid.uuid4())
        self.timestamp  = timestamp or datetime.utcnow().isoformat() + "Z"
        self.source     = source          # e.g. "sim-endpoint", "linux-auth"
        self.host       = host
        self.user       = user
        self.event_type = event_type      # auth_fail | process_start | dns_query | …
        self.severity   = severity        # info | low | medium | high
        self.summary    = summary
        self.raw        = raw if isinstance(raw, str) else json.dumps(raw)
        self.fields     = fields or {}    # src_ip, dest_ip, process_name, …

    def to_dict(self) -> dict:
        return {
            "event_id":   self.event_id,
            "timestamp":  self.timestamp,
            "source":     self.source,
            "host":       self.host,
            "user":       self.user,
            "event_type": self.event_type,
            "severity":   self.severity,
            "summary":    self.summary,
            "raw":        self.raw,
            "fields":     self.fields,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NormalizedEvent":
        e = cls.__new__(cls)
        e.event_id   = d["event_id"]
        e.timestamp  = d["timestamp"]
        e.source     = d["source"]
        e.host       = d["host"]
        e.user       = d.get("user")
        e.event_type = d["event_type"]
        e.severity   = d["severity"]
        e.summary    = d["summary"]
        e.raw        = d["raw"]
        e.fields     = d.get("fields") or {}
        if isinstance(e.fields, str):
            e.fields = json.loads(e.fields)
        return e


# ── SQLite helpers ────────────────────────────────────────────────────────────

def get_db(path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db(path: str = DB_PATH):
    """Create all tables if they don't exist."""
    con = get_db(path)
    cur = con.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS raw_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at TEXT    NOT NULL,
        source      TEXT    NOT NULL,
        payload     TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS normalized_events (
        event_id    TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL,
        source      TEXT NOT NULL,
        host        TEXT NOT NULL,
        user        TEXT,
        event_type  TEXT NOT NULL,
        severity    TEXT NOT NULL DEFAULT 'info',
        summary     TEXT NOT NULL,
        raw         TEXT NOT NULL,
        fields      TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS alerts (
        alert_id      TEXT PRIMARY KEY,
        created_at    TEXT NOT NULL,
        rule_id       TEXT NOT NULL,
        rule_name     TEXT NOT NULL,
        severity      TEXT NOT NULL,
        event_id      TEXT NOT NULL,
        host          TEXT NOT NULL,
        user          TEXT,
        summary       TEXT NOT NULL,
        status        TEXT NOT NULL DEFAULT 'open',
        notes         TEXT,
        snoozed_until TEXT,
        hit_count     INTEGER NOT NULL DEFAULT 1,
        last_hit_at   TEXT,
        attack_technique_id   TEXT,
        attack_technique_name TEXT,
        attack_tactic         TEXT,
        FOREIGN KEY (event_id) REFERENCES normalized_events(event_id)
    );

    CREATE TABLE IF NOT EXISTS alert_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id   TEXT NOT NULL,
        created_at TEXT NOT NULL,
        note       TEXT NOT NULL,
        FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
    );

    CREATE TABLE IF NOT EXISTS suppressions (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id          TEXT NOT NULL,
        rule_name        TEXT NOT NULL,
        scope            TEXT NOT NULL,
        match_value      TEXT,
        created_at       TEXT NOT NULL,
        expires_at       TEXT,
        suppressed_hits  INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON suppressions(rule_id);
    CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id);

    CREATE TABLE IF NOT EXISTS rule_hits (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        hit_at      TEXT    NOT NULL,
        rule_id     TEXT    NOT NULL,
        rule_name   TEXT    NOT NULL,
        event_id    TEXT    NOT NULL,
        matched_on  TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS source_health (
        source      TEXT PRIMARY KEY,
        last_seen   TEXT NOT NULL,
        events_1h   INTEGER NOT NULL DEFAULT 0,
        events_24h  INTEGER NOT NULL DEFAULT 0,
        status      TEXT NOT NULL DEFAULT 'unknown'
    );

    CREATE INDEX IF NOT EXISTS idx_ne_timestamp  ON normalized_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_ne_event_type ON normalized_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_ne_source     ON normalized_events(source);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

    CREATE TABLE IF NOT EXISTS iocs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        type        TEXT    NOT NULL,
        value       TEXT    NOT NULL,
        verdict     TEXT    NOT NULL DEFAULT 'malicious',
        score       INTEGER NOT NULL DEFAULT 75,
        tags        TEXT    NOT NULL DEFAULT '[]',
        source      TEXT    NOT NULL,
        description TEXT    NOT NULL DEFAULT '',
        actor       TEXT    NOT NULL DEFAULT '',
        added_at    TEXT    NOT NULL,
        expires_at  TEXT,
        feed_id     INTEGER,
        UNIQUE(type, value)
    );

    CREATE TABLE IF NOT EXISTS ip_reputation_cache (
        ip          TEXT PRIMARY KEY,
        verdict     TEXT NOT NULL,
        score       INTEGER NOT NULL DEFAULT 0,
        tags        TEXT NOT NULL DEFAULT '[]',
        source      TEXT NOT NULL,
        checked_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ti_feeds (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        url         TEXT NOT NULL UNIQUE,
        feed_type   TEXT NOT NULL DEFAULT 'ip',
        format      TEXT NOT NULL DEFAULT 'plain',
        tags        TEXT NOT NULL DEFAULT '[]',
        verdict     TEXT NOT NULL DEFAULT 'malicious',
        score       INTEGER NOT NULL DEFAULT 75,
        description TEXT NOT NULL DEFAULT '',
        enabled     INTEGER NOT NULL DEFAULT 1,
        added_at    TEXT NOT NULL,
        last_fetched TEXT,
        last_count  INTEGER,
        last_error  TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
    CREATE INDEX IF NOT EXISTS idx_iocs_feed       ON iocs(feed_id);
    """)
    con.commit()
    con.close()
    migrate_db(path)
    print(f"[DB] Initialized at {path}")


def migrate_db(path: str = DB_PATH):
    """
    Safe ALTER TABLE migrations for users upgrading an existing database.
    Each statement is attempted independently; failures are silently ignored
    because SQLite raises an error if a column already exists.
    """
    con = get_db(path)
    migrations = [
        # Feature: snooze
        "ALTER TABLE alerts ADD COLUMN snoozed_until TEXT",
        # Feature: deduplication counters
        "ALTER TABLE alerts ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE alerts ADD COLUMN last_hit_at TEXT",
        # Feature: ATT&CK tagging
        "ALTER TABLE alerts ADD COLUMN attack_technique_id TEXT",
        "ALTER TABLE alerts ADD COLUMN attack_technique_name TEXT",
        "ALTER TABLE alerts ADD COLUMN attack_tactic TEXT",
        # Feature: append-only notes history
        """CREATE TABLE IF NOT EXISTS alert_notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id   TEXT NOT NULL,
            created_at TEXT NOT NULL,
            note       TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id)",
        # Feature: suppressions
        """CREATE TABLE IF NOT EXISTS suppressions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id          TEXT NOT NULL,
            rule_name        TEXT NOT NULL,
            scope            TEXT NOT NULL,
            match_value      TEXT,
            created_at       TEXT NOT NULL,
            expires_at       TEXT,
            suppressed_hits  INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON suppressions(rule_id)",
        # Feature: threat intelligence
        """CREATE TABLE IF NOT EXISTS iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT    NOT NULL,
            value       TEXT    NOT NULL,
            verdict     TEXT    NOT NULL DEFAULT 'malicious',
            score       INTEGER NOT NULL DEFAULT 75,
            tags        TEXT    NOT NULL DEFAULT '[]',
            source      TEXT    NOT NULL,
            description TEXT    NOT NULL DEFAULT '',
            actor       TEXT    NOT NULL DEFAULT '',
            added_at    TEXT    NOT NULL,
            expires_at  TEXT,
            feed_id     INTEGER,
            UNIQUE(type, value)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value)",
        """CREATE TABLE IF NOT EXISTS ip_reputation_cache (
            ip          TEXT PRIMARY KEY,
            verdict     TEXT NOT NULL,
            score       INTEGER NOT NULL DEFAULT 0,
            tags        TEXT NOT NULL DEFAULT '[]',
            source      TEXT NOT NULL,
            checked_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS ti_feeds (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            url         TEXT NOT NULL UNIQUE,
            feed_type   TEXT NOT NULL DEFAULT 'ip',
            format      TEXT NOT NULL DEFAULT 'plain',
            tags        TEXT NOT NULL DEFAULT '[]',
            verdict     TEXT NOT NULL DEFAULT 'malicious',
            score       INTEGER NOT NULL DEFAULT 75,
            description TEXT NOT NULL DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            added_at    TEXT NOT NULL,
            last_fetched TEXT,
            last_count  INTEGER,
            last_error  TEXT
        )""",
    ]
    for sql in migrations:
        try:
            con.execute(sql)
            con.commit()
        except Exception:
            pass  # column/table already exists — safe to ignore
    con.close()
