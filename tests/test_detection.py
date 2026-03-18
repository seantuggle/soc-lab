"""
tests/test_detection.py — Unit tests for the detection engine

Run with:  pytest tests/ -v
"""
import sys, json, sqlite3, tempfile, os
sys.path.insert(0, ".")

import pytest
from shared.schema import NormalizedEvent, init_db, get_db
from services.detection.main import (
    _match_single, _match_timewindow, _match_fail_then_success,
    _already_alerted, _write_alert, load_rules
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Create a fresh SQLite DB for each test."""
    db_path = str(tmp_path / "test.db")
    os.environ["DB_PATH"] = db_path
    init_db(db_path)
    return db_path


def _make_event(**kwargs) -> NormalizedEvent:
    defaults = dict(source="sim-endpoint", host="test-host",
                    event_type="auth_fail", summary="test", raw={})
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


def _insert_event(con, event: NormalizedEvent):
    con.execute("""
        INSERT OR IGNORE INTO normalized_events
            (event_id, timestamp, source, host, user, event_type, severity, summary, raw, fields)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        event.event_id, event.timestamp, event.source, event.host,
        event.user, event.event_type, event.severity, event.summary,
        event.raw, json.dumps(event.fields)
    ))
    con.commit()


# ── _match_single ─────────────────────────────────────────────────────────────

class TestMatchSingle:

    def test_exact_event_type_match(self):
        event = _make_event(event_type="user_created")
        rule  = {"id": "R1", "name": "N", "match": {"event_type": "user_created"}}
        matched, conditions = _match_single(event, rule)
        assert matched is True
        assert len(conditions) == 1

    def test_exact_event_type_no_match(self):
        event = _make_event(event_type="auth_fail")
        rule  = {"id": "R1", "name": "N", "match": {"event_type": "user_created"}}
        matched, _ = _match_single(event, rule)
        assert matched is False

    def test_regex_match(self):
        event = _make_event(event_type="process_start",
                            fields={"command_line": "powershell -EncodedCommand abc"})
        rule = {"id": "R1", "name": "N", "match": {
            "event_type": "process_start",
            "fields.command_line": "~(?i)encodedcommand"
        }}
        matched, conditions = _match_single(event, rule)
        assert matched is True

    def test_regex_no_match(self):
        event = _make_event(event_type="process_start",
                            fields={"command_line": "nginx -g daemon off"})
        rule = {"id": "R1", "name": "N", "match": {
            "fields.command_line": "~(?i)encodedcommand"
        }}
        matched, _ = _match_single(event, rule)
        assert matched is False

    def test_list_membership_match(self):
        event = _make_event(event_type="auth_fail")
        rule = {"id": "R1", "name": "N", "match": {
            "event_type": ["auth_fail", "auth_success"]
        }}
        matched, _ = _match_single(event, rule)
        assert matched is True

    def test_list_membership_no_match(self):
        event = _make_event(event_type="dns_query")
        rule = {"id": "R1", "name": "N", "match": {
            "event_type": ["auth_fail", "auth_success"]
        }}
        matched, _ = _match_single(event, rule)
        assert matched is False

    def test_missing_field_no_match(self):
        event = _make_event(event_type="auth_fail")  # no fields.src_ip
        rule = {"id": "R1", "name": "N", "match": {"fields.src_ip": "1.2.3.4"}}
        matched, _ = _match_single(event, rule)
        assert matched is False

    def test_and_conditions_all_must_match(self):
        event = _make_event(event_type="process_start",
                            fields={"file_path": "/tmp/evil.sh", "command_line": "bash"})
        rule = {"id": "R1", "name": "N", "match": {
            "event_type": "process_start",
            "fields.file_path": "~/tmp/",
        }}
        matched, _ = _match_single(event, rule)
        assert matched is True

    def test_empty_match_block_no_match(self):
        event = _make_event()
        rule = {"id": "R1", "name": "N", "match": {}}
        matched, _ = _match_single(event, rule)
        assert matched is False

    def test_impossible_travel_rule(self):
        event = _make_event(event_type="impossible_travel")
        rule = {"id": "R1", "name": "N", "match": {"event_type": "impossible_travel"}}
        matched, conditions = _match_single(event, rule)
        assert matched is True


# ── _match_timewindow ─────────────────────────────────────────────────────────

class TestMatchTimeWindow:

    def test_fires_when_threshold_met(self, tmp_db):
        con = get_db(tmp_db)
        ip = "1.2.3.4"
        # Insert 5 auth_fail events from same IP
        for _ in range(5):
            e = _make_event(event_type="auth_fail", fields={"src_ip": ip})
            _insert_event(con, e)

        # The 6th event is the trigger
        trigger = _make_event(event_type="auth_fail", fields={"src_ip": ip})
        rule = {"id": "BF001", "name": "BF", "severity": "high", "window": {
            "field": "fields.src_ip", "event_type": "auth_fail", "count": 5, "seconds": 60
        }}
        matched, conditions = _match_timewindow(trigger, rule, con)
        assert matched is True
        assert len(conditions) == 1
        con.close()

    def test_does_not_fire_below_threshold(self, tmp_db):
        con = get_db(tmp_db)
        ip = "9.9.9.9"
        for _ in range(2):
            e = _make_event(event_type="auth_fail", fields={"src_ip": ip})
            _insert_event(con, e)

        trigger = _make_event(event_type="auth_fail", fields={"src_ip": ip})
        rule = {"id": "BF001", "name": "BF", "severity": "high", "window": {
            "field": "fields.src_ip", "event_type": "auth_fail", "count": 5, "seconds": 60
        }}
        matched, _ = _match_timewindow(trigger, rule, con)
        assert matched is False
        con.close()

    def test_wrong_event_type_skipped(self, tmp_db):
        con = get_db(tmp_db)
        trigger = _make_event(event_type="auth_success")  # not auth_fail
        rule = {"id": "BF001", "name": "BF", "severity": "high", "window": {
            "field": "fields.src_ip", "event_type": "auth_fail", "count": 5, "seconds": 60
        }}
        matched, _ = _match_timewindow(trigger, rule, con)
        assert matched is False
        con.close()


# ── _match_fail_then_success ──────────────────────────────────────────────────

class TestMatchFailThenSuccess:

    def test_fires_on_success_after_failures(self, tmp_db):
        con = get_db(tmp_db)
        ip = "5.5.5.5"
        for _ in range(4):
            e = _make_event(event_type="auth_fail", fields={"src_ip": ip})
            _insert_event(con, e)

        success = _make_event(event_type="auth_success", fields={"src_ip": ip}, user="victim")
        rule = {"id": "BF002", "name": "CredStuff", "type": "fail_then_success",
                "severity": "high", "fail_threshold": 3, "window_seconds": 300}
        matched, conditions = _match_fail_then_success(success, rule, con)
        assert matched is True
        con.close()

    def test_does_not_fire_without_prior_failures(self, tmp_db):
        con = get_db(tmp_db)
        success = _make_event(event_type="auth_success", fields={"src_ip": "7.7.7.7"})
        rule = {"id": "BF002", "name": "CredStuff", "type": "fail_then_success",
                "severity": "high", "fail_threshold": 3, "window_seconds": 300}
        matched, _ = _match_fail_then_success(success, rule, con)
        assert matched is False
        con.close()

    def test_only_fires_on_auth_success(self, tmp_db):
        con = get_db(tmp_db)
        event = _make_event(event_type="auth_fail", fields={"src_ip": "1.2.3.4"})
        rule = {"id": "BF002", "name": "CredStuff", "type": "fail_then_success",
                "severity": "high", "fail_threshold": 3, "window_seconds": 300}
        matched, _ = _match_fail_then_success(event, rule, con)
        assert matched is False
        con.close()


# ── _write_alert and _already_alerted ─────────────────────────────────────────

class TestAlertWriting:

    def test_alert_written_to_db(self, tmp_db):
        con = get_db(tmp_db)
        event = _make_event(event_type="user_created", user="backdoor")
        _insert_event(con, event)
        rule = {"id": "USR001", "name": "New User", "severity": "high"}
        _write_alert(con, rule, event, ["event_type == user_created"])

        row = con.execute("SELECT * FROM alerts WHERE rule_id='USR001'").fetchone()
        assert row is not None
        assert row["status"] == "open"
        assert row["severity"] == "high"
        con.close()

    def test_rule_hit_written(self, tmp_db):
        con = get_db(tmp_db)
        event = _make_event(event_type="user_created")
        _insert_event(con, event)
        rule = {"id": "USR001", "name": "New User", "severity": "high"}
        _write_alert(con, rule, event, ["event_type == user_created"])

        row = con.execute("SELECT * FROM rule_hits WHERE rule_id='USR001'").fetchone()
        assert row is not None
        con.close()

    def test_already_alerted_prevents_duplicate(self, tmp_db):
        con = get_db(tmp_db)
        event = _make_event(event_type="user_created")
        _insert_event(con, event)
        rule = {"id": "USR001", "name": "New User", "severity": "high"}
        _write_alert(con, rule, event, [])
        # Should not raise, but _already_alerted should return True now
        assert _already_alerted(con, "USR001", event.event_id) is True
        con.close()

    def test_not_yet_alerted(self, tmp_db):
        con = get_db(tmp_db)
        assert _already_alerted(con, "NONEXISTENT", "fake-event-id") is False
        con.close()


# ── Rule loading ──────────────────────────────────────────────────────────────

class TestRuleLoading:

    def test_rules_load_from_directory(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text("""
- id: TEST001
  name: Test Rule
  severity: medium
  match:
    event_type: auth_fail
""")
        os.environ["RULES_DIR"] = str(tmp_path)
        from importlib import reload
        import services.detection.main as det
        reload(det)
        rules = det.load_rules()
        assert any(r["id"] == "TEST001" for r in rules)

    def test_malformed_rule_file_skipped(self, tmp_path, capsys):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{{{{ invalid yaml")
        os.environ["RULES_DIR"] = str(tmp_path)
        from importlib import reload
        import services.detection.main as det
        reload(det)
        rules = det.load_rules()  # should not raise
        # malformed file skipped gracefully
        assert isinstance(rules, list)
