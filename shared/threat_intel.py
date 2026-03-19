"""
shared/threat_intel.py — Threat Intelligence enrichment

Provides:
  - Local IOC database lookup  (offline, instant)
  - IP reputation cache        (checks AbuseIPDB / VirusTotal if API keys set)
  - Public feed ingestion      (Abuse.ch, Emerging Threats blocklists)
  - enrich_threat_intel(event) — mutates event.fields in-place

IOC types supported: ip, domain, hash

Fields added to event.fields:
  src_ip_ti_verdict    : "malicious" | "suspicious" | "clean" | "unknown"
  src_ip_ti_score      : int 0-100
  src_ip_ti_source     : str  e.g. "AbuseIPDB" or "local-ioc"
  src_ip_ti_tags       : list e.g. ["ssh-brute","tor-exit"]
  src_ip_ti_actor      : str  threat actor name if known
  dns_query_ti_verdict : same shape for DNS query field
  dns_query_ti_tags    : list

API keys (optional — all features work offline without them):
  ABUSEIPDB_API_KEY  — https://www.abuseipdb.com/api (free tier: 1000 req/day)
  VIRUSTOTAL_API_KEY — https://www.virustotal.com/gui/my-apikey (free: 500/day)

Set via environment variables or docker-compose.yml environment block.
"""
from __future__ import annotations
import os, json, logging, ipaddress, re, hashlib
from datetime import datetime, timedelta
from typing import Optional
import urllib.request
import urllib.error

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")

# How long to cache reputation results (hours)
CACHE_TTL_HOURS = int(os.environ.get("TI_CACHE_TTL_HOURS", "24"))

# Confidence threshold for AbuseIPDB to call something malicious (0-100)
ABUSEIPDB_THRESHOLD = int(os.environ.get("ABUSEIPDB_THRESHOLD", "25"))

# ── Built-in IOC seed data ────────────────────────────────────────────────────
# A small hand-curated list covering the simulator IPs and well-known bad actors.
# Real IOCs come from the feed manager. This ensures the lab has something to
# show even with no network access and no feeds configured.

BUILTIN_IOCS = [
    # Tor exit nodes used in the simulator
    {"type": "ip",     "value": "185.220.101.34", "tags": ["tor-exit","brute-force"],
     "verdict": "malicious", "score": 90, "actor": "Unknown",
     "source": "builtin", "description": "Known Tor exit node, frequently used in SSH brute force campaigns"},
    {"type": "ip",     "value": "185.220.101.35", "tags": ["tor-exit"],
     "verdict": "malicious", "score": 85, "actor": "Unknown",
     "source": "builtin", "description": "Known Tor exit node"},
    {"type": "ip",     "value": "45.33.32.156",   "tags": ["vps","scanner"],
     "verdict": "suspicious", "score": 60, "actor": "Unknown",
     "source": "builtin", "description": "VPS IP associated with scanning activity"},
    {"type": "ip",     "value": "91.108.56.12",   "tags": ["telegram-infra"],
     "verdict": "suspicious", "score": 40, "actor": "Unknown",
     "source": "builtin", "description": "Telegram infrastructure — may be C2 relay"},
    # Known C2 domains used in the simulator
    {"type": "domain", "value": "c2server.tk",    "tags": ["c2","malware"],
     "verdict": "malicious", "score": 95, "actor": "Unknown",
     "source": "builtin", "description": "Simulated C2 domain (.tk TLD)"},
    {"type": "domain", "value": "malware-update.pw", "tags": ["c2","dropper"],
     "verdict": "malicious", "score": 95, "actor": "Unknown",
     "source": "builtin", "description": "Simulated malware update domain"},
    {"type": "domain", "value": "exfil.xyz",      "tags": ["exfiltration"],
     "verdict": "malicious", "score": 90, "actor": "Unknown",
     "source": "builtin", "description": "Simulated exfiltration domain"},
    {"type": "domain", "value": "login-verify.ru", "tags": ["phishing"],
     "verdict": "malicious", "score": 85, "actor": "Unknown",
     "source": "builtin", "description": "Simulated phishing domain"},
    {"type": "domain", "value": "support-help.top", "tags": ["phishing","c2"],
     "verdict": "malicious", "score": 80, "actor": "Unknown",
     "source": "builtin", "description": "Simulated phishing/C2 domain"},
    {"type": "domain", "value": "cdn-assets.icu",  "tags": ["c2"],
     "verdict": "suspicious", "score": 65, "actor": "Unknown",
     "source": "builtin", "description": "Simulated suspicious CDN domain"},
]

# ── Built-in public feed definitions ─────────────────────────────────────────

BUILTIN_FEEDS = [
    {
        "name":        "Abuse.ch Feodo Tracker (C2 IPs)",
        "url":         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_type":   "ip",
        "format":      "plain",    # one entry per line, # = comment
        "tags":        ["c2","feodo","banking-trojan"],
        "verdict":     "malicious",
        "score":       90,
        "description": "Feodo Tracker blocks IPs used by Feodo/Emotet/TrickBot C2 servers",
    },
    {
        "name":        "Abuse.ch URLhaus (Malware URLs)",
        "url":         "https://urlhaus.abuse.ch/downloads/text/",
        "feed_type":   "domain",
        "format":      "plain",
        "tags":        ["malware","urlhaus","dropper"],
        "verdict":     "malicious",
        "score":       85,
        "description": "URLhaus tracks URLs used to distribute malware",
    },
    {
        "name":        "Emerging Threats Compromised IPs",
        "url":         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_type":   "ip",
        "format":      "plain",
        "tags":        ["compromised","scanner"],
        "verdict":     "malicious",
        "score":       75,
        "description": "Emerging Threats list of known compromised/scanning IPs",
    },
    {
        "name":        "Abuse.ch SSLBL (Botnet C2 IPs)",
        "url":         "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "feed_type":   "ip",
        "format":      "csv_skip2",  # skip first 2 comment lines, col 0 = IP
        "tags":        ["ssl-blacklist","c2","botnet"],
        "verdict":     "malicious",
        "score":       88,
        "description": "SSL certificate blacklist for botnet C2 servers",
    },
]

# ── DB helpers (lazy import to avoid circular deps) ───────────────────────────

def _get_db():
    from shared.schema import get_db, DB_PATH
    return get_db(DB_PATH)


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ── IOC lookup ────────────────────────────────────────────────────────────────

def lookup_ioc(ioc_type: str, value: str) -> dict | None:
    """
    Check the local IOC table for a match.
    Returns the IOC row dict or None.
    ioc_type: "ip" | "domain" | "hash"
    """
    if not value:
        return None
    try:
        con = _get_db()
        row = con.execute(
            "SELECT * FROM iocs WHERE type=? AND LOWER(value)=LOWER(?) "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (ioc_type, value.strip(), _now())
        ).fetchone()
        con.close()
        if row:
            r = dict(row)
            if isinstance(r.get("tags"), str):
                try:
                    r["tags"] = json.loads(r["tags"])
                except Exception:
                    r["tags"] = []
            return r
    except Exception as exc:
        log.debug("IOC lookup failed: %s", exc)
    return None


def add_ioc(ioc_type: str, value: str, verdict: str, score: int,
            tags: list, source: str, description: str = "",
            actor: str = "", expires_at: str | None = None,
            feed_id: int | None = None) -> bool:
    """Insert or update an IOC in the local database."""
    try:
        con = _get_db()
        con.execute("""
            INSERT INTO iocs (type, value, verdict, score, tags, source,
                              description, actor, added_at, expires_at, feed_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(type, value) DO UPDATE SET
                verdict=excluded.verdict, score=excluded.score,
                tags=excluded.tags, source=excluded.source,
                description=excluded.description, actor=excluded.actor,
                added_at=excluded.added_at, expires_at=excluded.expires_at,
                feed_id=excluded.feed_id
        """, (
            ioc_type, value.strip().lower(), verdict, score,
            json.dumps(tags), source, description, actor,
            _now(), expires_at, feed_id
        ))
        con.commit()
        con.close()
        return True
    except Exception as exc:
        log.error("add_ioc failed: %s", exc)
        return False


# ── Reputation cache ──────────────────────────────────────────────────────────

def _get_cached_reputation(ip: str) -> dict | None:
    """Return a cached reputation result if it's still fresh."""
    try:
        con  = _get_db()
        row  = con.execute(
            "SELECT * FROM ip_reputation_cache WHERE ip=? AND expires_at > ?",
            (ip, _now())
        ).fetchone()
        con.close()
        if row:
            d = dict(row)
            if isinstance(d.get("tags"), str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except Exception:
                    d["tags"] = []
            return d
    except Exception:
        pass
    return None


def _set_cached_reputation(ip: str, verdict: str, score: int,
                           tags: list, source: str) -> None:
    expires = (datetime.utcnow() + timedelta(hours=CACHE_TTL_HOURS)).isoformat() + "Z"
    try:
        con = _get_db()
        con.execute("""
            INSERT INTO ip_reputation_cache (ip, verdict, score, tags, source, checked_at, expires_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                verdict=excluded.verdict, score=excluded.score,
                tags=excluded.tags, source=excluded.source,
                checked_at=excluded.checked_at, expires_at=excluded.expires_at
        """, (ip, verdict, score, json.dumps(tags), source, _now(), expires))
        con.commit()
        con.close()
    except Exception as exc:
        log.debug("Cache write failed: %s", exc)


# ── AbuseIPDB lookup ──────────────────────────────────────────────────────────

def _query_abuseipdb(ip: str) -> dict | None:
    """
    Query AbuseIPDB v2 API.
    Returns normalized result dict or None on failure.
    Requires ABUSEIPDB_API_KEY env var.
    """
    if not ABUSEIPDB_KEY:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url)
        req.add_header("Key", ABUSEIPDB_KEY)
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        d     = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        tags_raw = d.get("usageType", "") or ""
        tags  = [t.strip() for t in tags_raw.split(",") if t.strip()]
        if d.get("isTor"):
            tags.append("tor")
        if d.get("isWhitelisted"):
            verdict = "clean"
        elif score >= ABUSEIPDB_THRESHOLD:
            verdict = "malicious" if score >= 70 else "suspicious"
        else:
            verdict = "clean"

        return {
            "verdict": verdict,
            "score":   score,
            "tags":    tags,
            "source":  "AbuseIPDB",
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            log.warning("AbuseIPDB rate limit hit for %s", ip)
        else:
            log.debug("AbuseIPDB error %s for %s: %s", exc.code, ip, exc)
    except Exception as exc:
        log.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
    return None


# ── VirusTotal lookup ─────────────────────────────────────────────────────────

def _query_virustotal_ip(ip: str) -> dict | None:
    """
    Query VirusTotal IP address report endpoint.
    Requires VIRUSTOTAL_API_KEY env var.
    """
    if not VIRUSTOTAL_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", VIRUSTOTAL_KEY)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        stats = (data.get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1
        score      = int(((malicious + suspicious * 0.5) / total) * 100)

        if malicious >= 3:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "verdict": verdict,
            "score":   score,
            "tags":    [],
            "source":  "VirusTotal",
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            log.warning("VirusTotal rate limit hit for %s", ip)
        elif exc.code == 404:
            pass   # IP not in VT — not an error
        else:
            log.debug("VirusTotal error %s for %s", exc.code, ip)
    except Exception as exc:
        log.debug("VirusTotal lookup failed for %s: %s", ip, exc)
    return None


# ── Main reputation lookup ────────────────────────────────────────────────────

def get_ip_reputation(ip: str) -> dict:
    """
    Full reputation lookup for one IP:
      1. Check local IOC table (instant)
      2. Check reputation cache (instant if fresh)
      3. Query AbuseIPDB (if key set)
      4. Query VirusTotal  (if key set, AbuseIPDB didn't fire)
      5. Return unknown if nothing found

    Returns:
      { "verdict": str, "score": int, "tags": list,
        "source": str, "from_cache": bool }
    """
    if not ip:
        return {"verdict": "unknown", "score": 0, "tags": [], "source": "none"}

    # 1. Local IOC table
    ioc = lookup_ioc("ip", ip)
    if ioc:
        return {
            "verdict":    ioc["verdict"],
            "score":      ioc["score"],
            "tags":       ioc.get("tags", []),
            "source":     ioc["source"],
            "actor":      ioc.get("actor", ""),
            "description": ioc.get("description", ""),
            "from_cache": False,
            "from_ioc":   True,
        }

    # 2. Reputation cache
    cached = _get_cached_reputation(ip)
    if cached:
        cached["from_cache"] = True
        return cached

    # 3. AbuseIPDB
    result = _query_abuseipdb(ip)

    # 4. VirusTotal (fallback or supplement)
    if not result:
        result = _query_virustotal_ip(ip)

    if result:
        _set_cached_reputation(ip, result["verdict"], result["score"],
                               result["tags"], result["source"])
        result["from_cache"] = False
        return result

    # 5. Unknown
    return {"verdict": "unknown", "score": 0, "tags": [], "source": "none", "from_cache": False}


# ── Domain IOC lookup ─────────────────────────────────────────────────────────

def get_domain_reputation(domain: str) -> dict:
    """Check local IOC table for a domain. No external API for domains."""
    if not domain:
        return {"verdict": "unknown", "score": 0, "tags": [], "source": "none"}

    # Strip subdomains progressively: evil.sub.example.com → sub.example.com → example.com
    parts = domain.lower().strip().split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        ioc = lookup_ioc("domain", candidate)
        if ioc:
            return {
                "verdict":     ioc["verdict"],
                "score":       ioc["score"],
                "tags":        ioc.get("tags", []),
                "source":      ioc["source"],
                "actor":       ioc.get("actor", ""),
                "description": ioc.get("description", ""),
                "from_ioc":    True,
            }
    return {"verdict": "unknown", "score": 0, "tags": [], "source": "none"}


# ── Event enrichment ──────────────────────────────────────────────────────────

def enrich_threat_intel(event) -> None:
    """
    Mutates event.fields in-place with TI data.
    Checks src_ip and dns_query fields.
    Skips internal IPs.
    """
    # IP reputation
    src_ip = event.fields.get("src_ip")
    if src_ip and not event.fields.get("src_ip_internal"):
        rep = get_ip_reputation(str(src_ip))
        if rep and rep.get("verdict") != "unknown":
            event.fields["src_ip_ti_verdict"] = rep["verdict"]
            event.fields["src_ip_ti_score"]   = rep["score"]
            event.fields["src_ip_ti_source"]  = rep.get("source", "")
            event.fields["src_ip_ti_tags"]    = rep.get("tags", [])
            if rep.get("actor"):
                event.fields["src_ip_ti_actor"] = rep["actor"]
            if rep.get("description"):
                event.fields["src_ip_ti_desc"] = rep["description"]
            log.info("TI enrichment: %s → %s (score=%s, src=%s)",
                     src_ip, rep["verdict"], rep["score"], rep.get("source","?"))

    # Domain reputation (dns_query field)
    dns_q = event.fields.get("dns_query")
    if dns_q:
        drep = get_domain_reputation(str(dns_q))
        if drep and drep.get("verdict") != "unknown":
            event.fields["dns_query_ti_verdict"] = drep["verdict"]
            event.fields["dns_query_ti_score"]   = drep["score"]
            event.fields["dns_query_ti_source"]  = drep.get("source", "")
            event.fields["dns_query_ti_tags"]    = drep.get("tags", [])
            if drep.get("actor"):
                event.fields["dns_query_ti_actor"] = drep["actor"]


# ── Feed ingestion ────────────────────────────────────────────────────────────

def fetch_feed(feed: dict) -> tuple[int, str]:
    """
    Download and parse a TI feed. Returns (count_added, error_message).
    feed dict must have: url, feed_type, format, tags, verdict, score, feed_id (from DB)
    """
    url       = feed["url"]
    feed_type = feed["feed_type"]   # "ip" | "domain"
    fmt       = feed.get("format", "plain")
    tags      = feed.get("tags", [])
    verdict   = feed.get("verdict", "malicious")
    score     = feed.get("score", 75)
    feed_id   = feed.get("feed_id")
    source    = feed.get("name", url)

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "SOC-Lab/1.0 TI-Feed-Fetcher")
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, f"Download failed: {exc}"

    count = 0
    lines = raw.splitlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Skip comment lines
        if line.startswith("#") or line.startswith(";"):
            continue

        # CSV format: skip header rows
        if fmt == "csv_skip2" and i < 2:
            continue

        # Extract the IOC value
        if fmt == "csv_skip2":
            value = line.split(",")[0].strip().strip('"')
        else:
            # plain: first whitespace-separated token
            value = line.split()[0] if line.split() else ""

        if not value:
            continue

        # Validate based on type
        if feed_type == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                # Could be a CIDR — skip for now
                continue
            # Skip private IPs from public feeds
            try:
                if any(ipaddress.ip_address(value) in net for net in [
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("127.0.0.0/8"),
                ]):
                    continue
            except Exception:
                continue

        elif feed_type == "domain":
            # Basic domain validation
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$', value):
                continue
            if "/" in value or ":" in value:
                # It's a URL not a domain — extract hostname
                try:
                    from urllib.parse import urlparse
                    value = urlparse(value).hostname or ""
                    if not value:
                        continue
                except Exception:
                    continue

        ok = add_ioc(
            ioc_type=feed_type, value=value, verdict=verdict,
            score=score, tags=tags, source=source,
            description=f"From feed: {source}", feed_id=feed_id,
        )
        if ok:
            count += 1

    return count, ""


def seed_builtin_iocs() -> int:
    """Insert the built-in IOC seed data. Safe to call multiple times."""
    count = 0
    for ioc in BUILTIN_IOCS:
        ok = add_ioc(
            ioc_type=ioc["type"], value=ioc["value"],
            verdict=ioc["verdict"], score=ioc["score"],
            tags=ioc["tags"], source=ioc["source"],
            description=ioc.get("description", ""),
            actor=ioc.get("actor", ""),
        )
        if ok:
            count += 1
    return count


def seed_builtin_feeds() -> None:
    """Insert the built-in feed definitions if they don't already exist."""
    try:
        con = _get_db()
        for f in BUILTIN_FEEDS:
            existing = con.execute(
                "SELECT id FROM ti_feeds WHERE url=?", (f["url"],)
            ).fetchone()
            if not existing:
                con.execute("""
                    INSERT INTO ti_feeds
                        (name, url, feed_type, format, tags, verdict, score,
                         description, enabled, added_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (
                    f["name"], f["url"], f["feed_type"], f["format"],
                    json.dumps(f["tags"]), f["verdict"], f["score"],
                    f.get("description", ""), 0, _now()
                ))
        con.commit()
        con.close()
    except Exception as exc:
        log.error("seed_builtin_feeds failed: %s", exc)
