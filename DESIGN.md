# SOC Lab — Design Document

Architecture decisions, rationale, and extension guide.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         SOC Lab Pipeline                         │
│                                                                  │
│  ┌────────────┐    HTTP     ┌─────────────┐    SQLite            │
│  │ Simulator  │──POST/ingest│  Ingestion  │──────────────────┐  │
│  └────────────┘             │  (FastAPI)  │                  │  │
│                             └─────────────┘                  ▼  │
│  ┌────────────┐    file     ┌─────────────┐  ┌──────────────────┐│
│  │ auth.log   │──tail──────▶│  Normalizer │  │  SQLite DB       ││
│  └────────────┘             └─────────────┘  │                  ││
│                                              │  raw_events      ││
│                             ┌─────────────┐  │  normalized_ev.. ││
│                             │  Detection  │◀─│  alerts          ││
│                             │  Engine     │  │  rule_hits       ││
│                             └─────────────┘  │  source_health   ││
│                                    │         └──────────────────┘│
│                                    ▼                  ▲          │
│                             ┌─────────────┐           │          │
│                             │  Dashboard  │───────────┘          │
│                             │  (FastAPI)  │                      │
│                             └─────────────┘                      │
│                               http://localhost:8080              │
└──────────────────────────────────────────────────────────────────┘
```

### Why three separate services?

1. **Ingestion** is the only service exposed to external log sources. Isolating it
   means a buggy parser can't crash the dashboard or detection engine.

2. **Detection** is CPU-bound (regex, time-window queries). Running it separately
   means slow rules don't block log ingestion.

3. **Dashboard** is read-heavy. It can be restarted independently without losing
   any data (everything lives in SQLite).

In production, these would be separate containers (or serverless functions) with
a message queue (Kafka, Redis Streams) between ingestion and detection.

---

## Key Design Decisions

### SQLite instead of PostgreSQL/Elasticsearch

**Why:** SQLite is zero-config, ships in Python's stdlib, and is powerful enough
for a lab processing <10k events/day. The WAL journal mode allows concurrent
reads and writes from multiple processes.

**When to upgrade:** If you start ingesting real production logs or need
full-text search, swap to PostgreSQL (change `get_db()`) or add an Elasticsearch
sink alongside SQLite.

### Polling detection (not streaming)

The detection engine polls `normalized_events` every 5 seconds rather than
subscribing to a stream. This is simpler to understand and debug — you can
pause the detector, replay events, and reason about state. The downside is up
to 5s detection latency.

**When to upgrade:** Add a Redis Streams or Kafka topic between ingestion and
detection for sub-second alerting.

### YAML rules with Python evaluation

Rules are stored as YAML and evaluated by Python code. This is more transparent
than a compiled rule engine — you can read the entire evaluator in ~100 lines
of `detection/main.py`.

The rule evaluator supports three modes:
- `match:` block — single-event AND conditions (exact, regex, list)
- `window:` block — time-window counting (brute force patterns)
- `type: fail_then_success` — sequence correlation

**When to upgrade:** Add a proper rule DSL, support `OR` conditions,
add aggregation functions (count, sum, distinct), or import Sigma rules directly.

### Jinja2 server-side templates (not React)

The dashboard is rendered server-side with Jinja2 and uses HTMX for partial
updates. No JavaScript build step, no `node_modules`. The entire dashboard
is two HTML files you can read and modify without any tooling.

---

## Database Schema

```sql
-- Raw events: exactly what was received, never modified
raw_events (id, received_at, source, payload)

-- Normalized events: canonical event schema
normalized_events (
  event_id TEXT PRIMARY KEY,  -- UUID
  timestamp TEXT,             -- ISO8601
  source TEXT,                -- "sim-endpoint" | "linux-auth" | ...
  host TEXT,
  user TEXT,                  -- nullable
  event_type TEXT,            -- auth_fail | process_start | ...
  severity TEXT,              -- info | low | medium | high
  summary TEXT,               -- human-readable one-liner
  raw TEXT,                   -- original payload (JSON string)
  fields TEXT                 -- JSON object: source-specific enrichment
)

-- Alerts: one per rule-event pair
alerts (
  alert_id TEXT PRIMARY KEY,
  created_at TEXT,
  rule_id TEXT,
  rule_name TEXT,
  severity TEXT,
  event_id TEXT,              -- FK → normalized_events
  host TEXT,
  user TEXT,
  summary TEXT,
  status TEXT,                -- open | investigating | closed
  notes TEXT                  -- analyst notes
)

-- Rule hits: every time a rule matches, regardless of dedup
rule_hits (id, hit_at, rule_id, rule_name, event_id, matched_on)

-- Source health: one row per source, upserted on every event
source_health (source, last_seen, events_1h, events_24h, status)
```

---

## Adding a New Log Source

**Time required:** ~30 minutes

### 1. Write a parser function

In `shared/normalizers.py`:

```python
def parse_my_source(raw: str | dict) -> NormalizedEvent:
    """Convert a raw my-source event into a NormalizedEvent."""
    # Extract fields from raw
    # Return NormalizedEvent(source="my-source", ...)
    # Raise ValueError if the line is unrecognized
    ...
```

### 2. Register the parser

```python
PARSERS["my-source"] = parse_my_source
```

### 3. Write tests

In `tests/test_normalizers.py`, add a `TestMySourceParser` class with at least:
- Happy path: a normal event parses correctly
- Field extraction: key fields are in `e.fields`
- Unknown line: `ValueError` is raised for unrecognized input

### 4. Send events

```bash
curl -X POST http://localhost:8001/ingest \
  -H "Content-Type: application/json" \
  -d '{"source": "my-source", "payload": "your raw event here"}'
```

### 5. Write rules

Add a YAML file in `rules/` targeting your new `event_type` values.

---

## Adding a New Rule Type

Currently supported rule types:

| Matcher | Key fields | Use case |
|---|---|---|
| `match:` block | field: value or ~regex | Single-event pattern |
| `window:` block | field, event_type, count, seconds | Threshold detection |
| `type: fail_then_success` | fail_threshold, window_seconds | Sequence correlation |

To add a new matcher (e.g., `type: ratio_anomaly`):

1. Add a `_match_ratio_anomaly()` function in `services/detection/main.py`
   following the existing pattern (takes `event, rule, con`, returns `(bool, list[str])`)

2. Call it in `_evaluate()` after the existing matchers

3. Document the new fields in this file

---

## Production Hardening Checklist

This is a learning lab, not a production SIEM. If you want to harden it:

- [ ] Add authentication to the dashboard (OAuth2, API keys)
- [ ] Add TLS to the ingestion endpoint
- [ ] Use PostgreSQL instead of SQLite (concurrent writers)
- [ ] Add a message queue (Redis/Kafka) between ingestion and detection
- [ ] Add structured logging with correlation IDs
- [ ] Add rate limiting to the ingestion endpoint
- [ ] Add input validation and size limits on payloads
- [ ] Run services as non-root users in Docker
- [ ] Add health check monitoring (Prometheus metrics endpoint)
- [ ] Set up log rotation for the SQLite WAL file

---

## Performance Characteristics

| Metric | Expected (lab) | Bottleneck |
|---|---|---|
| Ingest throughput | ~500 events/sec | SQLite write lock |
| Detection latency | 1–5 seconds | Poll interval |
| Dashboard query time | <50ms | SQLite index scan |
| Max comfortable DB size | ~10M events | SQLite file size |

For the learning use case (hundreds of events/day), these numbers are irrelevant.
The architecture is intentionally simple.
