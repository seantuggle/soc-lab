"""
shared/normalizers.py — Convert raw source payloads → NormalizedEvent

Each parser function accepts a raw dict (already parsed JSON or a line of text)
and returns a NormalizedEvent (or raises ValueError if the payload can't be parsed).

Adding a new source = add a new parser function + register it in PARSERS dict.
"""
from __future__ import annotations
import re, json
from datetime import datetime
from shared.schema import NormalizedEvent


# ── sim-endpoint parser ───────────────────────────────────────────────────────

def parse_sim_endpoint(raw: dict) -> NormalizedEvent:
    """
    Events emitted by tools/generate_events.py  (JSON dicts).
    Expected keys: event_type, host, user, timestamp, ...
    """
    etype = raw.get("event_type", "unknown")
    host  = raw.get("host", "unknown-host")
    user  = raw.get("user")
    ts    = raw.get("timestamp", datetime.utcnow().isoformat() + "Z")

    # Build normalized fields dict from whatever the simulator provides
    fields = {k: v for k, v in raw.items()
              if k not in ("event_type", "host", "user", "timestamp", "summary", "severity")}

    # Derive severity
    severity = raw.get("severity", _infer_severity_sim(etype))

    summary = raw.get("summary") or _summary_sim(etype, raw)

    return NormalizedEvent(
        source     = "sim-endpoint",
        host       = host,
        event_type = etype,
        summary    = summary,
        raw        = raw,
        severity   = severity,
        user       = user,
        fields     = fields,
        timestamp  = ts,
    )


def _infer_severity_sim(etype: str) -> str:
    mapping = {
        "auth_fail":        "low",
        "auth_success":     "info",
        "process_start":    "medium",
        "dns_query":        "info",
        "dns_suspicious":   "high",
        "user_created":     "high",
        "web_request":      "info",
        "web_404":          "low",
        "web_401":          "low",
        "file_access":      "low",
        "impossible_travel":"high",
    }
    return mapping.get(etype, "info")


def _summary_sim(etype: str, raw: dict) -> str:
    user = raw.get("user", "?")
    host = raw.get("host", "?")
    ip   = raw.get("src_ip", raw.get("fields", {}).get("src_ip", "?"))
    summaries = {
        "auth_fail":        f"Login failed for {user} from {ip}",
        "auth_success":     f"Login success for {user} from {ip}",
        "process_start":    f"Process started: {raw.get('process_name','?')} on {host}",
        "dns_query":        f"DNS query: {raw.get('dns_query','?')} from {host}",
        "dns_suspicious":   f"Suspicious DNS query: {raw.get('dns_query','?')}",
        "user_created":     f"New user created: {raw.get('new_user', user)} on {host}",
        "web_request":      f"HTTP {raw.get('status_code','?')} {raw.get('path','/')}",
        "impossible_travel":f"Impossible travel for {user}: {raw.get('location_a','?')} → {raw.get('location_b','?')}",
    }
    return summaries.get(etype, f"Event {etype} on {host}")


# ── linux-auth parser ─────────────────────────────────────────────────────────

# Example auth.log line:
# Mar 17 12:34:56 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
_AUTH_FAIL_RE  = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
_AUTH_OK_RE    = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
_NEW_USER_RE   = re.compile(r"useradd\[.*\]: new user: name=([^,\s]+)")
_SUDO_RE       = re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.*)")

def parse_linux_auth(raw: str | dict) -> NormalizedEvent:
    """
    Parses a single line from /var/log/auth.log (passed as a string)
    or a dict with key 'line' (used by the file-tailer).
    """
    if isinstance(raw, dict):
        line = raw.get("line", "")
        host = raw.get("host", "linux-host")
    else:
        line = raw
        host = "linux-host"

    ts = datetime.utcnow().isoformat() + "Z"

    m = _AUTH_FAIL_RE.search(line)
    if m:
        return NormalizedEvent(
            source     = "linux-auth",
            host       = host,
            event_type = "auth_fail",
            summary    = f"SSH login failed for {m.group(1)} from {m.group(2)}",
            raw        = line,
            severity   = "low",
            user       = m.group(1),
            fields     = {"src_ip": m.group(2), "method": "ssh"},
            timestamp  = ts,
        )

    m = _AUTH_OK_RE.search(line)
    if m:
        return NormalizedEvent(
            source     = "linux-auth",
            host       = host,
            event_type = "auth_success",
            summary    = f"SSH login success for {m.group(1)} from {m.group(2)}",
            raw        = line,
            severity   = "info",
            user       = m.group(1),
            fields     = {"src_ip": m.group(2), "method": "ssh"},
            timestamp  = ts,
        )

    m = _NEW_USER_RE.search(line)
    if m:
        return NormalizedEvent(
            source     = "linux-auth",
            host       = host,
            event_type = "user_created",
            summary    = f"New user account created: {m.group(1)}",
            raw        = line,
            severity   = "high",
            user       = m.group(1),
            fields     = {"new_user": m.group(1)},
            timestamp  = ts,
        )

    m = _SUDO_RE.search(line)
    if m:
        return NormalizedEvent(
            source     = "linux-auth",
            host       = host,
            event_type = "process_start",
            summary    = f"sudo by {m.group(1)}: {m.group(2)[:80]}",
            raw        = line,
            severity   = "medium",
            user       = m.group(1),
            fields     = {"command_line": m.group(2), "via": "sudo"},
            timestamp  = ts,
        )

    raise ValueError(f"Unrecognized auth.log line: {line[:80]}")


# ── Registry ──────────────────────────────────────────────────────────────────

PARSERS: dict[str, callable] = {
    "sim-endpoint": parse_sim_endpoint,
    "linux-auth":   parse_linux_auth,
}


def normalize(source: str, raw: str | dict) -> NormalizedEvent:
    """
    Entry point: look up the right parser by source name and run it.
    Raises ValueError if source is unknown or parsing fails.
    """
    if source not in PARSERS:
        raise ValueError(f"Unknown source: {source!r}. Registered: {list(PARSERS)}")
    return PARSERS[source](raw)
