"""
services/ingestion/main.py — HTTP ingestion endpoint

POST /ingest          body: {"source": "sim-endpoint", "payload": {...}}
POST /ingest/batch    body: [{"source":..., "payload":...}, ...]
GET  /health          returns per-source health
GET  /sources         list registered sources
"""
from __future__ import annotations
import os, sys, json, logging, threading
from datetime import datetime, timezone
from contextlib import asynccontextmanager

sys.path.insert(0, "/app")

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any

from shared.schema    import init_db, get_db, DB_PATH
from shared.normalizers import normalize, PARSERS
from shared.enrichment  import enrich_event
from shared.threat_intel import enrich_threat_intel, seed_builtin_iocs, seed_builtin_feeds

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s [ingestion] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── thread-safe counters ──────────────────────────────────────────────────────
_lock = threading.Lock()
_counters: dict[str, dict] = {}  # source → {count, last_seen}


def _bump(source: str):
    with _lock:
        if source not in _counters:
            _counters[source] = {"count": 0, "last_seen": None}
        _counters[source]["count"]     += 1
        _counters[source]["last_seen"]  = datetime.utcnow().isoformat() + "Z"


# ── lifecycle ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Initializing database …")
    init_db(DB_PATH)
    n = seed_builtin_iocs()
    log.info("Seeded %d built-in IOCs", n)
    seed_builtin_feeds()
    log.info("Built-in TI feeds registered")
    _start_log_tailer()
    yield
    log.info("Shutting down ingestion service.")


app = FastAPI(title="SOC Lab – Ingestion", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Pydantic models ───────────────────────────────────────────────────────────

class IngestRequest(BaseModel):
    source: str
    payload: Any          # raw event — dict or string


# ── core ingestion logic ──────────────────────────────────────────────────────

def _store_raw(source: str, payload: Any) -> int:
    con = get_db(DB_PATH)
    cur = con.execute(
        "INSERT INTO raw_events (received_at, source, payload) VALUES (?,?,?)",
        (datetime.utcnow().isoformat()+"Z", source,
         payload if isinstance(payload, str) else json.dumps(payload))
    )
    rowid = cur.lastrowid
    con.commit(); con.close()
    return rowid


def _store_normalized(event) -> None:
    con = get_db(DB_PATH)
    con.execute("""
        INSERT OR IGNORE INTO normalized_events
            (event_id, timestamp, source, host, user, event_type, severity, summary, raw, fields)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        event.event_id, event.timestamp, event.source, event.host,
        event.user, event.event_type, event.severity, event.summary,
        event.raw, json.dumps(event.fields)
    ))
    con.commit(); con.close()


def _update_source_health(source: str) -> None:
    con = get_db(DB_PATH)
    now = datetime.utcnow().isoformat() + "Z"

    # Count events in last 1h and 24h
    row1h  = con.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE source=? AND timestamp > datetime('now','-1 hour')",
        (source,)).fetchone()[0]
    row24h = con.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE source=? AND timestamp > datetime('now','-24 hours')",
        (source,)).fetchone()[0]

    con.execute("""
        INSERT INTO source_health (source, last_seen, events_1h, events_24h, status)
        VALUES (?,?,?,?,'active')
        ON CONFLICT(source) DO UPDATE SET
            last_seen=excluded.last_seen,
            events_1h=excluded.events_1h,
            events_24h=excluded.events_24h,
            status='active'
    """, (source, now, row1h, row24h))
    con.commit(); con.close()


def ingest_one(source: str, payload: Any) -> dict:
    """Store raw, normalize, store normalized, update health. Returns result dict."""
    _store_raw(source, payload)
    _bump(source)
    try:
        event = normalize(source, payload)
        enrich_event(event)            # geo: country, ASN, internal flag
        enrich_threat_intel(event)     # TI: IOC match, reputation, tags
        _store_normalized(event)
        _update_source_health(source)
        log.info("Ingested %s event_id=%s type=%s", source, event.event_id[:8], event.event_type)
        return {"status": "ok", "event_id": event.event_id, "event_type": event.event_type}
    except ValueError as exc:
        log.warning("Normalization skipped for %s: %s", source, exc)
        return {"status": "skipped", "reason": str(exc)}


# ── routes ────────────────────────────────────────────────────────────────────

@app.post("/ingest")
async def ingest(req: IngestRequest, bg: BackgroundTasks):
    result = ingest_one(req.source, req.payload)
    return result


@app.post("/ingest/batch")
async def ingest_batch(events: list[IngestRequest]):
    results = []
    for e in events:
        results.append(ingest_one(e.source, e.payload))
    return {"processed": len(results), "results": results}


@app.get("/health")
async def health():
    con = get_db(DB_PATH)
    sources = [dict(r) for r in con.execute("SELECT * FROM source_health").fetchall()]
    con.close()
    return {
        "status": "ok",
        "sources": sources,
        "in_memory_counts": dict(_counters),
    }


@app.get("/sources")
async def sources():
    return {"registered_sources": list(PARSERS.keys())}


# ── optional log-file tailer ──────────────────────────────────────────────────

def _start_log_tailer():
    auth_log = os.environ.get("AUTH_LOG_PATH", "")
    if not auth_log or not os.path.exists(auth_log):
        log.info("AUTH_LOG_PATH not set or not found — skipping log tailer.")
        return

    def tail():
        log.info("Tailing %s …", auth_log)
        hostname = os.environ.get("LOG_HOST", "linux-host")
        with open(auth_log) as f:
            f.seek(0, 2)   # seek to end
            while True:
                line = f.readline()
                if line:
                    ingest_one("linux-auth", {"line": line.rstrip(), "host": hostname})
                else:
                    import time; time.sleep(0.5)

    t = threading.Thread(target=tail, daemon=True, name="log-tailer")
    t.start()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=False)
