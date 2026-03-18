# SOC Lab — Lab Guide

This guide walks you through the SOC Lab from first boot to writing your own
detection rules. Work through it top-to-bottom for the best learning experience.

---

## What You'll Learn

- How logs flow from a source through normalization into storage
- How a detection engine evaluates rules against a stream of events
- How analysts triage alerts: investigate → decide → close
- How to write and tune your own Sigma-style YAML rules
- How to add a new log source with its own parser

---

## Phase 1 — Get It Running (Day 1)

### Step 1: Start the lab

```bash
docker compose up --build
```

Watch the logs. You should see:
```
ingestion  | [DB] Initialized at /app/db/soc.db
ingestion  | INFO:     Application startup complete.
detection  | Detection engine started. Polling every 5s …
dashboard  | INFO:     Application startup complete.
simulator  | ✓ Ingestion service is ready.
```

### Step 2: Open the dashboard

Go to **http://localhost:8080**

You'll see the main SOC dashboard with:
- **Open Alerts** counter (starts at 0)
- **Events (1h)** counter
- **Active Sources** from the simulator
- **Event Stream** showing live events

### Step 3: Generate your first attack

In a second terminal:
```bash
docker compose run --rm simulator python generate_events.py --scenario brute_force
```

**Expected output:**
```
[SCENARIO] SSH Brute Force — 8 failures from single IP
  ✓ [sim-endpoint] auth_fail             event_id=a1b2c3d4…
  ✓ [sim-endpoint] auth_fail             event_id=e5f6g7h8…
  ... (8 total)
```

**What to check:**
- Refresh the dashboard (it auto-refreshes every 10s)
- Open Alerts should jump from 0 to 1+
- The event stream should show 8 `auth_fail` entries
- You should see the BF001 (SSH Brute Force) alert

---

## Phase 2 — Understand the Pipeline (Day 1–2)

### Exercise 2.1 — Trace an event end-to-end

Run one event manually and trace it through every table:

```bash
curl -X POST http://localhost:8001/ingest \
  -H "Content-Type: application/json" \
  -d '{"source": "sim-endpoint", "payload": {
    "event_type": "user_created",
    "host": "my-test-host",
    "user": "root",
    "new_user": "backdoor99",
    "timestamp": "2025-01-01T00:00:00Z"
  }}'
```

Now connect to the SQLite database and verify each step:

```bash
# Docker
docker compose exec ingestion sqlite3 /app/db/soc.db

# Local
sqlite3 db/soc.db
```

```sql
-- 1. Was the raw event stored?
SELECT id, source, substr(payload,1,80) FROM raw_events ORDER BY id DESC LIMIT 1;

-- 2. Was it normalized?
SELECT event_id, event_type, host, user, severity FROM normalized_events ORDER BY rowid DESC LIMIT 1;

-- 3. Did the rule fire?
SELECT rule_id, rule_name, matched_on FROM rule_hits ORDER BY id DESC LIMIT 1;

-- 4. Was an alert created?
SELECT alert_id, rule_name, severity, status FROM alerts ORDER BY rowid DESC LIMIT 1;

-- 5. What's in the fields JSON?
SELECT json_extract(fields,'$.new_user') AS new_user FROM normalized_events ORDER BY rowid DESC LIMIT 1;
```

**Expected:** You should find rows in all four tables. The alert should have
status `open` and severity `high`.

### Exercise 2.2 — Understand the normalized schema

Look at the `normalized_events` table schema:

```sql
.schema normalized_events
```

Which fields are always present? Which are nullable? Now look at a record with
fields that vary by event type:

```sql
SELECT event_type, fields FROM normalized_events LIMIT 10;
```

Notice how `fields` is a JSON column — different event types store different
keys there. This is the normalized envelope.

---

## Phase 3 — Investigate Alerts (Day 2–3)

### Exercise 3.1 — Work through the investigation view

1. Trigger the credential stuffing scenario:
   ```bash
   docker compose run --rm simulator python generate_events.py --scenario cred_stuff
   ```

2. Open the dashboard: http://localhost:8080

3. Click **Investigate →** on the "Credential Stuffing" alert

4. In the investigation view, answer these questions:
   - What IP address did the attack come from?
   - Which user account was compromised?
   - How many failures preceded the success?
   - What are the "Related Events" showing?

5. Set the alert status to **Investigating**, add a note like
   `"Confirmed external IP, user password reset initiated"`, and save.

6. Go back to the dashboard — the alert should now show `investigating`.

### Exercise 3.2 — Triage the impossible travel alert

```bash
docker compose run --rm simulator python generate_events.py --scenario impossible_travel
```

In the investigation view:
- What are the two locations?
- What is the time gap between them?
- Is this a false positive or true positive? How would you decide?

---

## Phase 4 — Writing Rules (Day 3–4)

### Exercise 4.1 — Tune an existing rule

The brute force rule (BF001) currently fires at **5 failures in 60 seconds**.
Open `rules/brute_force.yml` and change the threshold:

```yaml
window:
  count: 3       # lower threshold = more sensitive
  seconds: 120   # longer window
```

Restart the detection service (Docker: `docker compose restart detection`)
and re-run the brute force scenario with only 3 failures:

```bash
docker compose run --rm simulator python generate_events.py \
  --scenario brute_force --count 3
```

Does it fire now? What happens if you set `count: 2`?

**Key insight:** Lower thresholds = more alerts (higher false positive rate).
Higher thresholds = fewer alerts (higher false negative rate). This trade-off
is central to detection engineering.

### Exercise 4.2 — Write a new rule from scratch

**Goal:** Write a rule that fires when a login succeeds from an external IP
(not in the 10.x.x.x range) to a sensitive host named `server-db01`.

Create a new file `rules/my_rules.yml`:

```yaml
- id: MY001
  name: External Login to Database Server
  description: >
    A successful login to the database server from an external IP.
    This should never happen in a properly segmented network.
  severity: high
  match:
    event_type: auth_success
    host: server-db01
  tags: [network-segmentation, database, lateral-movement]
  false_positive_notes: >
    Legitimate if running a bastion host that forwards sessions.
    Verify against your network topology.
  response: |
    1. Verify the source IP against your jump host list.
    2. Check what commands were run after login.
    3. If unknown IP: disable the account and investigate.
```

Restart detection, then generate events:
```bash
docker compose restart detection
docker compose run --rm simulator python generate_events.py --scenario brute_force
```

The scenario logs to random hosts. Generate until `server-db01` is hit.
Or send a targeted event:

```bash
curl -X POST http://localhost:8001/ingest \
  -H "Content-Type: application/json" \
  -d '{"source": "sim-endpoint", "payload": {
    "event_type": "auth_success",
    "host": "server-db01",
    "user": "dbadmin",
    "src_ip": "91.108.56.12"
  }}'
```

Does your rule fire?

### Exercise 4.3 — Add a new field

The `impossible_travel` event currently stores `location_a` and `location_b`
in the `fields` dict. Add a `gap_hours` derived field.

Open `shared/normalizers.py` → `parse_sim_endpoint()` → find where `fields` is
built. Add logic:

```python
if etype == "impossible_travel":
    gap_min = float(raw.get("gap_minutes", 0))
    fields["gap_hours"] = round(gap_min / 60, 2)
```

Write a rule that uses this new field:

```yaml
- id: TRAVEL002
  name: Impossible Travel - Fast (<30 min)
  severity: critical
  match:
    event_type: impossible_travel
    fields.gap_hours: ~^0\.0[0-4]   # less than ~4 minutes
```

---

## Phase 5 — Add a New Log Source (Day 4–5)

### Exercise 5.1 — Add a simulated web server log parser

Web server logs look like this (Combined Log Format):

```
192.168.1.1 - alice [17/Mar/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 512
```

**Step 1:** Add a parser in `shared/normalizers.py`:

```python
import re as _re

_APACHE_RE = _re.compile(
    r'(?P<ip>[\d.]+) .+ \[.+\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+)'
)

def parse_apache_access(raw: str | dict) -> NormalizedEvent:
    line = raw if isinstance(raw, str) else raw.get("line", "")
    m = _APACHE_RE.search(line)
    if not m:
        raise ValueError(f"Unrecognized Apache log: {line[:80]}")
    status = int(m.group("status"))
    etype  = "web_request"
    if status == 404: etype = "web_404"
    if status in (401, 403): etype = "web_401"
    return NormalizedEvent(
        source     = "apache-access",
        host       = "web-server",
        event_type = etype,
        summary    = f"HTTP {status} {m.group('method')} {m.group('path')}",
        raw        = line,
        severity   = "low" if status >= 400 else "info",
        fields     = {"src_ip": m.group("ip"), "path": m.group("path"),
                      "method": m.group("method"), "status_code": status},
    )
```

**Step 2:** Register it:
```python
PARSERS["apache-access"] = parse_apache_access
```

**Step 3:** Test it:
```bash
curl -X POST http://localhost:8001/ingest \
  -H "Content-Type: application/json" \
  -d '{"source": "apache-access", "payload": {
    "line": "10.0.0.5 - bob [17/Mar/2025:12:00:00 +0000] \"GET /admin HTTP/1.1\" 404 123"
  }}'
```

**Step 4:** Write a test in `tests/test_normalizers.py`:

```python
def test_apache_404():
    from shared.normalizers import parse_apache_access
    e = parse_apache_access('10.0.0.5 - - [17/Mar/2025:12:00:00 +0000] "GET /admin HTTP/1.1" 404 0')
    assert e.event_type == "web_404"
    assert e.fields["src_ip"] == "10.0.0.5"
    assert e.fields["status_code"] == 404
```

---

## Troubleshooting

### "Cannot connect to ingestion service"
```bash
# Check if containers are running
docker compose ps

# Check ingestion logs
docker compose logs ingestion

# Manually hit health endpoint
curl http://localhost:8001/health
```

### Dashboard shows no events
- Wait 10 seconds (the dashboard auto-refreshes)
- Check that the simulator is sending events: `docker compose logs simulator`
- Verify the ingestion service is accepting: check `/health`

### Alerts not firing
- Detection polls every 5 seconds — wait a moment
- Check detection logs: `docker compose logs detection`
- Verify rule syntax: `python -c "import yaml; yaml.safe_load(open('rules/brute_force.yml'))"`
- Make sure `count` events exist within the `seconds` window

### Database is corrupted / reset needed
```bash
docker compose down
rm db/soc.db
docker compose up
```

### Tests failing
```bash
# Make sure you're in the project root
cd soc-lab
pytest tests/ -v --tb=short
```

---

## Checkpoint: What You Should Have Learned

After completing this lab, you should be able to explain:

1. **Log normalization:** Why a common schema matters and how different sources
   map to it differently.

2. **Detection logic:** The difference between single-event rules (pattern match),
   time-window rules (count threshold), and correlation rules (sequence matching).

3. **False positive tuning:** Why every threshold is a trade-off, and how to
   adjust sensitivity using rule parameters.

4. **Alert triage:** What information you need to decide if an alert is a true
   positive, and how to document your investigation.

5. **Extending the system:** How to add a new source, a new field, or a new rule
   without breaking existing functionality.

---

## Going Further

Once you've completed the exercises, try:

- **Add GeoIP enrichment:** Resolve IPs to countries using `geoip2` and add a
  `country` field to `fields`. Update TRAVEL001 to filter by country pair.

- **Add email alerting:** Use `smtplib` to send an email when a `high` severity
  alert fires.

- **Sigma rule converter:** Sigma (https://github.com/SigmaHQ/sigma) is the
  industry standard format. Write a converter from Sigma → SOC Lab YAML.

- **Real SIEM comparison:** Export your alerts to JSON and import them into
  Elastic Security or Splunk's free tier. Compare the UI and query languages.

- **Add a MITRE ATT&CK tag:** Each rule already has a `tags` field. Extend the
  rule format to include an `attack_technique` field (e.g. `T1110` for brute
  force) and display it in the investigation view.
