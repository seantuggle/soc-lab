"""
shared/enrichment.py — IP address enrichment

Adds the following keys to event.fields for any event that has a src_ip:
  - src_ip_internal   : bool   — True if RFC-1918 / loopback / link-local
  - src_ip_country    : str    — 2-letter ISO code, e.g. "US", or "??"
  - src_ip_country_name: str   — Full name, e.g. "United States"
  - src_ip_asn        : str    — AS number + org, e.g. "AS13335 Cloudflare"

Strategy (in order of preference):
  1. If geoip2 is installed AND GEOIP_DB_PATH points to a GeoLite2-City.mmdb
     (or GeoLite2-Country.mmdb), use the MaxMind reader — most accurate.
  2. Otherwise fall back to a lightweight built-in lookup using ip-api.com
     public data embedded as a compact prefix table.  We ship a small
     hand-curated table covering the most common attacker ASNs and country
     blocks so the lab works completely offline for typical simulated IPs.
  3. For any IP not in the table, country = "??" and ASN = "unknown".

The MaxMind GeoLite2 databases are free.  Download instructions:
  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  Place the .mmdb file anywhere and set:
    GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

Usage:
  from shared.enrichment import enrich_event
  enrich_event(event)   # mutates event.fields in-place
"""
from __future__ import annotations
import ipaddress, os, logging
from typing import Optional

log = logging.getLogger(__name__)

# ── MaxMind geoip2 (optional) ────────────────────────────────────────────────

_geoip_reader = None
_geoip_tried  = False

def _get_geoip_reader():
    global _geoip_reader, _geoip_tried
    if _geoip_tried:
        return _geoip_reader
    _geoip_tried = True

    db_path = os.environ.get("GEOIP_DB_PATH", "")
    if not db_path or not os.path.exists(db_path):
        log.info("[enrichment] GEOIP_DB_PATH not set or not found — using built-in table.")
        return None

    try:
        import geoip2.database
        _geoip_reader = geoip2.database.Reader(db_path)
        log.info("[enrichment] MaxMind GeoIP reader loaded from %s", db_path)
    except ImportError:
        log.info("[enrichment] geoip2 package not installed — using built-in table.")
    except Exception as exc:
        log.warning("[enrichment] Failed to open GeoIP DB: %s", exc)
    return _geoip_reader


# ── Internal IP classification ────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ── Built-in prefix table (offline fallback) ─────────────────────────────────
# Format: (network_str, country_code, country_name, asn_str)
# Covers the simulated IPs used by generate_events.py plus common cloud/VPS ranges.
# Sorted by prefix length descending so more-specific matches win.

_PREFIX_TABLE = [
    # Tor exit nodes and known attacker infrastructure (used in simulator)
    ("185.220.101.0/24",  "DE", "Germany",        "AS205100 F3 Netze"),
    ("185.220.0.0/16",    "DE", "Germany",        "AS205100 F3 Netze"),
    ("45.33.32.0/24",     "US", "United States",  "AS63949 Akamai/Linode"),
    ("45.33.0.0/16",      "US", "United States",  "AS63949 Akamai/Linode"),
    ("91.108.56.0/22",    "NL", "Netherlands",    "AS62041 Telegram"),
    ("91.108.0.0/16",     "NL", "Netherlands",    "AS62041 Telegram"),
    ("203.0.113.0/24",    "ZZ", "Documentation",  "AS0 TEST-NET-3"),   # RFC 5737
    ("198.51.100.0/24",   "ZZ", "Documentation",  "AS0 TEST-NET-2"),   # RFC 5737
    # Common cloud providers
    ("35.0.0.0/8",        "US", "United States",  "AS15169 Google Cloud"),
    ("34.0.0.0/8",        "US", "United States",  "AS15169 Google Cloud"),
    ("52.0.0.0/8",        "US", "United States",  "AS16509 Amazon AWS"),
    ("54.0.0.0/8",        "US", "United States",  "AS16509 Amazon AWS"),
    ("13.0.0.0/8",        "US", "United States",  "AS8075  Microsoft Azure"),
    ("20.0.0.0/8",        "US", "United States",  "AS8075  Microsoft Azure"),
    ("104.16.0.0/12",     "US", "United States",  "AS13335 Cloudflare"),
    ("172.64.0.0/13",     "US", "United States",  "AS13335 Cloudflare"),
    # Country-level blocks (coarse fallbacks)
    ("1.0.0.0/8",         "AU", "Australia",      "AS1221  Telstra"),
    ("5.0.0.0/8",         "DE", "Germany",        "AS3320  Deutsche Telekom"),
    ("77.0.0.0/8",        "GB", "United Kingdom", "AS2856  BT"),
    ("78.0.0.0/8",        "RU", "Russia",         "AS8359  MTS"),
    ("79.0.0.0/8",        "RU", "Russia",         "AS8359  MTS"),
    ("80.0.0.0/8",        "FR", "France",         "AS3215  Orange"),
    ("82.0.0.0/8",        "DE", "Germany",        "AS3320  Deutsche Telekom"),
    ("89.0.0.0/8",        "RU", "Russia",         "AS12389 Rostelecom"),
    ("94.0.0.0/8",        "RU", "Russia",         "AS12389 Rostelecom"),
    ("103.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("106.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("112.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("113.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("116.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("117.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("118.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("119.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("121.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("122.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("125.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("176.0.0.0/8",       "RU", "Russia",         "AS12389 Rostelecom"),
    ("178.0.0.0/8",       "RU", "Russia",         "AS12389 Rostelecom"),
    ("185.0.0.0/8",       "EU", "Europe",         "AS0     Various EU"),
    ("188.0.0.0/8",       "RU", "Russia",         "AS8359  MTS"),
    ("193.0.0.0/8",       "NL", "Netherlands",    "AS1103  RIPE NCC"),
    ("194.0.0.0/8",       "GB", "United Kingdom", "AS786   JANET"),
    ("195.0.0.0/8",       "DE", "Germany",        "AS3320  Deutsche Telekom"),
    ("196.0.0.0/8",       "ZA", "South Africa",   "AS2018  TENET"),
    ("197.0.0.0/8",       "NG", "Nigeria",        "AS37148 MTN"),
    ("200.0.0.0/8",       "BR", "Brazil",         "AS4230  Embratel"),
    ("201.0.0.0/8",       "BR", "Brazil",         "AS4230  Embratel"),
    ("202.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("210.0.0.0/8",       "JP", "Japan",          "AS2527  NTT"),
    ("211.0.0.0/8",       "JP", "Japan",          "AS2527  NTT"),
    ("218.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("219.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("220.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("221.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
    ("222.0.0.0/8",       "CN", "China",          "AS4134  ChinaTelecom"),
]

# Pre-compile to ipaddress network objects, sorted most-specific first
_COMPILED_TABLE = sorted(
    [(ipaddress.ip_network(net, strict=False), cc, name, asn)
     for net, cc, name, asn in _PREFIX_TABLE],
    key=lambda x: x[0].prefixlen,
    reverse=True,
)


def _builtin_lookup(ip_str: str) -> tuple[str, str, str]:
    """Returns (country_code, country_name, asn_str) from the built-in table."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net, cc, name, asn in _COMPILED_TABLE:
            if addr in net:
                return cc, name, asn
    except ValueError:
        pass
    return "??", "Unknown", "unknown"


# ── MaxMind lookup ────────────────────────────────────────────────────────────

def _maxmind_lookup(ip_str: str) -> tuple[str, str, str] | None:
    """
    Returns (country_code, country_name, asn_str) using MaxMind geoip2,
    or None if the reader is unavailable or the IP is not in the DB.
    """
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        response = reader.city(ip_str)
        cc   = response.country.iso_code or "??"
        name = response.country.name     or "Unknown"
        # geoip2.City doesn't include ASN; use AS number from traits if available
        asn_str = "unknown"
        try:
            asn_str = f"AS{response.traits.autonomous_system_number} {response.traits.autonomous_system_organization}"
        except Exception:
            pass
        return cc, name, asn_str
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_ip(ip_str: str) -> dict:
    """
    Returns an enrichment dict for one IP address:
      {
        "internal":      bool,
        "country":       "US",
        "country_name":  "United States",
        "asn":           "AS13335 Cloudflare",
      }
    """
    if not ip_str or not isinstance(ip_str, str):
        return {}

    internal = _is_internal(ip_str)
    if internal:
        return {
            "internal":     True,
            "country":      "RFC1918",
            "country_name": "Internal Network",
            "asn":          "internal",
        }

    # Try MaxMind first, fall back to built-in table
    result = _maxmind_lookup(ip_str)
    if result is None:
        result = _builtin_lookup(ip_str)

    cc, name, asn = result
    return {
        "internal":     False,
        "country":      cc,
        "country_name": name,
        "asn":          asn,
    }


def enrich_event(event) -> None:
    """
    Mutates event.fields in-place.
    Looks for fields.src_ip and adds:
      src_ip_internal, src_ip_country, src_ip_country_name, src_ip_asn
    Also checks dest_ip if present.
    """
    for field_prefix in ("src_ip", "dest_ip"):
        ip_val = event.fields.get(field_prefix)
        if not ip_val:
            continue
        geo = enrich_ip(str(ip_val))
        if not geo:
            continue
        event.fields[f"{field_prefix}_internal"]     = geo.get("internal", False)
        event.fields[f"{field_prefix}_country"]      = geo.get("country", "??")
        event.fields[f"{field_prefix}_country_name"] = geo.get("country_name", "Unknown")
        event.fields[f"{field_prefix}_asn"]          = geo.get("asn", "unknown")
