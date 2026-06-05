#!/usr/bin/env python3
"""Approximate IP -> physical location (state / city) via a local MaxMind
GeoLite2-City database.

Google's audit `networkInfo` frequently gives only a country for an IP (no
`subdivisionCode`), and registry data (RDAP — see `ip_attribution.py`) gives the
block *owner*, not where the IP is used. This fills that gap with an **offline**
geolocation lookup, so no IPs leave the machine.

Setup: download the free `GeoLite2-City.mmdb` from MaxMind (a free account +
license key gets you the file; the key is only needed to *download* it — this
module just reads the file). It's found automatically in the usual
`geoipupdate` locations (`/opt/homebrew/var/GeoIP`, `/usr/local/var/GeoIP`,
`/usr/share/GeoIP`) or next to this module; set `GEOIP_CITY_DB` to override with
an explicit path (or `GEOIP_DIR` to add a directory). Without the DB, every
lookup returns `{}` and callers degrade to country-only — nothing breaks.

Note: it must be the **City** edition — `GeoLite2-Country.mmdb` has no
subdivisions, so it yields no state (and callers stay country-only).

Caveat: IP geolocation is an *estimate*, least reliable for carrier / business
ranges (different providers routinely disagree by a state or more). Treat the
result as directional, not authoritative — callers flag it as such.
"""
from __future__ import annotations

import ipaddress
import os
from functools import lru_cache

try:
    import maxminddb
except ImportError:  # dependency not synced — degrade rather than crash
    maxminddb = None

_DB_FILENAME = "GeoLite2-City.mmdb"
# Conventional geoipupdate / Homebrew locations, searched in order when
# GEOIP_CITY_DB isn't set. Last entry is the repo dir (drop-in convenience).
_DEFAULT_DB_DIRS = (
    "/opt/homebrew/var/GeoIP",   # Homebrew (Apple Silicon)
    "/usr/local/var/GeoIP",      # Homebrew (Intel)
    "/usr/share/GeoIP",          # Linux geoipupdate default
    os.path.dirname(os.path.abspath(__file__)),
)


def _resolve_db_path() -> str:
    """GeoLite2-City.mmdb path: `GEOIP_CITY_DB` if set, else the first existing
    match across `GEOIP_DIR` (if set) + the default GeoIP dirs."""
    explicit = os.environ.get("GEOIP_CITY_DB")
    if explicit:
        return explicit
    dirs = list(_DEFAULT_DB_DIRS)
    env_dir = os.environ.get("GEOIP_DIR")
    if env_dir:
        dirs.insert(0, env_dir)
    for d in dirs:
        candidate = os.path.join(d, _DB_FILENAME)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(_DEFAULT_DB_DIRS[-1], _DB_FILENAME)  # absent -> graceful


@lru_cache(maxsize=1)
def _reader():
    """Open the GeoLite2-City reader once, or None when unavailable."""
    if maxminddb is None:
        return None
    try:
        return maxminddb.open_database(_resolve_db_path())
    except Exception:
        return None


def geolocate(ip: str) -> dict:
    """Best-effort location for `ip`:
    ``{country_code, country, subdivision_code, subdivision, city}``.

    Empty dict when the DB is absent, the IP is non-global / malformed, or no
    record is found — so callers can always fall back to country-only.
    """
    reader = _reader()
    if not reader or not ip:
        return {}
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {}
    except ValueError:
        return {}
    try:
        rec = reader.get(ip)
    except Exception:
        return {}
    if not rec:
        return {}
    country = rec.get("country") or rec.get("registered_country") or {}
    subs = rec.get("subdivisions") or []
    sub = subs[0] if subs else {}
    city = rec.get("city") or {}
    cc = country.get("iso_code") or ""
    sub_iso = sub.get("iso_code") or ""
    return {
        "country_code": cc,
        "country": (country.get("names") or {}).get("en", ""),
        "subdivision_code": f"{cc}-{sub_iso}" if cc and sub_iso else sub_iso,
        "subdivision": (sub.get("names") or {}).get("en", ""),
        "city": (city.get("names") or {}).get("en", ""),
    }


def render_geo(geo: dict) -> str:
    """Format a `geolocate()` result as 'City, State, Country' — the most
    specific parts available. '' when empty."""
    parts = [geo.get("city"), geo.get("subdivision"), geo.get("country")]
    return ", ".join(p for p in parts if p)
