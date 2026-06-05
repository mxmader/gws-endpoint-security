#!/usr/bin/env python3
"""IP-address attribution via RDAP (the ICANN/RIR registration system).

Google's audit logs hand us a bare `ipAddress` with no ownership context (see
`docs/google_device_data_sources.md`). This module resolves an IP to its
**registered network owner** — the org that holds the address block at its
Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC) — so a sign-in
from a residential ISP, a cloud/VPN provider, or a corporate egress reads at a
glance.

How it works:
  - The IANA RDAP bootstrap (https://data.iana.org/rdap/) maps an IP to the
    authoritative RIR's RDAP endpoint. We query `<rir>/ip/<addr>` and read the
    registrant org out of the RFC 9083 response.
  - Results are cached on disk keyed by the registered CIDR, so every later IP
    that falls in the same block is a pure local lookup — no network call.
    Registration data is very slow-changing, so the cache stays valid for
    months (entries refetch lazily after `_STALE_AFTER`).

The cache file holds real IPs/CIDRs, so it is git-ignored — never commit it.

No API key, no binary database; only the `requests` dep (already vendored) plus
the standard library.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ip_attribution_cache.json"
)
_CACHE_VERSION = 1

# RDAP registration data barely changes; refetch a cached entry only after this.
_STALE_AFTER = timedelta(days=180)
# The IANA bootstrap (RIR -> RDAP URL map) changes even less; refresh monthly.
_BOOTSTRAP_STALE_AFTER = timedelta(days=30)
_BOOTSTRAP_URLS = {
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}

_USER_AGENT = "endpoint-security/ip_attribution (+https://github.com/; RDAP client)"
_MAX_WORKERS = 4
_MAX_RETRIES = 3

# Network used to cache a *failed* lookup, so a transient error doesn't make us
# re-hammer every neighbouring address. Coarse on purpose.
_NEG_PREFIX = {4: 24, 6: 48}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_stale(fetched_at: str | None, horizon: timedelta) -> bool:
    if not fetched_at:
        return True
    try:
        ts = datetime.fromisoformat(fetched_at)
    except ValueError:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return _now() - ts > horizon


# --------------------------------------------------------------------------- #
# On-disk cache
# --------------------------------------------------------------------------- #
class _Cache:
    """CIDR-keyed attribution cache plus the IANA bootstrap, persisted as one
    JSON file. Lookups resolve to the most-specific cached block containing the
    address."""

    def __init__(self, path: str = _CACHE_PATH):
        self.path = path
        self.networks: list[dict] = []
        self.bootstrap: dict = {}
        self._index: list[tuple] = []  # (ip_network, record)
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        if data.get("version") != _CACHE_VERSION:
            return  # Forward/backward incompatible — start fresh.
        self.networks = data.get("networks") or []
        self.bootstrap = data.get("bootstrap") or {}
        self._reindex()

    def _reindex(self) -> None:
        index: list[tuple] = []
        for rec in self.networks:
            try:
                net = ipaddress.ip_network(rec["cidr"], strict=False)
            except (KeyError, ValueError):
                continue
            index.append((net, rec))
        self._index = index

    def lookup(self, ip: ipaddress._BaseAddress) -> dict | None:
        """Most-specific cached record whose block contains `ip`, or None."""
        best: tuple | None = None
        for net, rec in self._index:
            if ip.version == net.version and ip in net:
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, rec)
        return best[1] if best else None

    def add(self, records: Iterable[dict]) -> None:
        for rec in records:
            self.networks.append(rec)
        self._reindex()

    def save(self) -> None:
        tmp = f"{self.path}.tmp"
        payload = {
            "version": _CACHE_VERSION,
            "bootstrap": self.bootstrap,
            "networks": self.networks,
        }
        with open(tmp, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------- #
# IANA RDAP bootstrap
# --------------------------------------------------------------------------- #
def _refresh_bootstrap(cache: _Cache, *, timeout: float) -> None:
    """Populate `cache.bootstrap` with parsed RIR prefix -> RDAP base maps,
    fetching the IANA files when missing or stale. Best-effort: on failure we
    keep whatever we had (possibly nothing)."""
    for family, url in _BOOTSTRAP_URLS.items():
        entry = cache.bootstrap.get(family) or {}
        if entry.get("services") and not _is_stale(
            entry.get("fetched_at"), _BOOTSTRAP_STALE_AFTER
        ):
            continue
        try:
            resp = requests.get(
                url, headers={"User-Agent": _USER_AGENT}, timeout=timeout
            )
            resp.raise_for_status()
            services = resp.json().get("services") or []
        except (requests.RequestException, ValueError):
            continue  # Keep the stale copy rather than wiping it.
        cache.bootstrap[family] = {
            "fetched_at": _now().isoformat(),
            "services": services,
        }


def _rdap_base_for(ip: ipaddress._BaseAddress, cache: _Cache) -> str | None:
    """Longest-prefix-matching RIR RDAP base URL for `ip` from the bootstrap."""
    family = "ipv4" if ip.version == 4 else "ipv6"
    services = (cache.bootstrap.get(family) or {}).get("services") or []
    best_len = -1
    best_url: str | None = None
    # Bootstrap service entry: [[cidr, ...], [rdap_base_url, ...]]
    for entry in services:
        prefixes, urls = (entry + [[], []])[:2]
        for prefix in prefixes:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if ip.version == net.version and ip in net and net.prefixlen > best_len:
                best_len = net.prefixlen
                best_url = urls[0] if urls else None
    return best_url


# --------------------------------------------------------------------------- #
# RDAP query + parse
# --------------------------------------------------------------------------- #
def _vcard_field(vcard_array: list, name: str) -> str:
    """Pull a field (e.g. 'fn', 'org') out of a jCard (RFC 7095) array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return ""
    for item in vcard_array[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == name:
            val = item[3]
            return val if isinstance(val, str) else ""
    return ""


def _iter_entities(entities: list):
    """Yield every entity, flattening RDAP's nested `entities` (RIPE nests the
    registrant/maintainer under the abuse contact, etc.)."""
    for ent in entities or []:
        yield ent
        yield from _iter_entities(ent.get("entities"))


# RIPE often tags each contact's `fn` with its role, e.g. "Cloudflare Abuse
# Contact" — strip that to recover the bare org name.
_CONTACT_SUFFIX_RE = re.compile(
    r"\s+(abuse|technical|administrative|registrant)\s+contact$", re.IGNORECASE
)


def _looks_like_handle(name: str, handle: str) -> bool:
    """True when `name` is just a registry handle, not an org name — e.g. a
    RIPE maintainer object (`MNT-CLOUDFLARE`, `SFR-MNT`) or `fn` echoing the
    entity handle. These are noise, never the entity we want."""
    n = (name or "").strip()
    if not n:
        return True
    if handle and n.upper() == handle.strip().upper():
        return True
    up = n.upper()
    return up.startswith("MNT-") or up.endswith("-MNT")


def _owner_from_entities(entities: list) -> str:
    """Best org/owner name across RDAP entities. Skips maintainer/NIC handles,
    prefers an actual organisation (vCard kind=org), then the registrant /
    admin / technical / abuse contact — with RIPE's "… Contact" role suffix
    stripped. Returns '' when only handles are present (caller falls back to the
    network name)."""
    by_role: dict[str, str] = {}
    org_name = ""
    fallback = ""
    for ent in _iter_entities(entities):
        vcard = ent.get("vcardArray") or []
        raw = _vcard_field(vcard, "fn") or _vcard_field(vcard, "org")
        if _looks_like_handle(raw, ent.get("handle") or ""):
            continue
        name = _CONTACT_SUFFIX_RE.sub("", raw).strip()
        if not name:
            continue
        if _vcard_field(vcard, "kind") == "org" and not org_name:
            org_name = name
        fallback = fallback or name
        for role in ent.get("roles") or []:
            by_role.setdefault(role, name)
    return (
        org_name
        or by_role.get("registrant")
        or by_role.get("administrative")
        or by_role.get("technical")
        or by_role.get("abuse")
        or fallback
    )


def _cidrs_from_response(resp: dict) -> list[str]:
    """Registered block(s) for the queried IP — from `cidr0_cidrs` when present
    (RFC 9083 cidr0 extension), else summarised from start/end addresses."""
    out: list[str] = []
    for c in resp.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix is not None and length is not None:
            try:
                out.append(str(ipaddress.ip_network(f"{prefix}/{length}", strict=False)))
            except ValueError:
                pass
    if out:
        return out
    start, end = resp.get("startAddress"), resp.get("endAddress")
    if start and end:
        try:
            nets = ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)
            )
            out = [str(n) for n in list(nets)[:8]]  # cap pathological ranges
        except (ValueError, TypeError):
            pass
    return out


def _http_get_json(url: str, *, timeout: float) -> dict | None:
    """GET with bounded retry, honouring Retry-After on 429/5xx. None on failure."""
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/rdap+json"}
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException:
            return None
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return None
        if resp.status_code == 404:
            return None  # Not found is authoritative, not transient.
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < _MAX_RETRIES - 1:
            try:
                delay = float(resp.headers.get("Retry-After", ""))
            except ValueError:
                delay = 1.0 * (attempt + 1)
            time.sleep(min(delay, 10.0))
            continue
        return None
    return None


def _query_rdap(ip_str: str, ip: ipaddress._BaseAddress, base: str, *, timeout: float) -> dict:
    """Look up one IP and return a cache record dict."""
    url = base.rstrip("/") + "/ip/" + ip_str
    resp = _http_get_json(url, timeout=timeout)
    if not resp:
        # Negative cache: coarse block so we don't re-hammer the neighbourhood.
        neg = ipaddress.ip_network(
            f"{ip}/{_NEG_PREFIX[ip.version]}", strict=False
        )
        return {
            "cidr": str(neg), "owner": "", "handle": "", "rir": _rir_label(base),
            "fetched_at": _now().isoformat(), "source": "error",
        }
    owner = _owner_from_entities(resp.get("entities") or [])
    handle = resp.get("handle") or ""
    netname = resp.get("name") or ""
    cidrs = _cidrs_from_response(resp) or [
        str(ipaddress.ip_network(f"{ip}/{_NEG_PREFIX[ip.version]}", strict=False))
    ]
    return {
        "cidr": cidrs[0],
        "extra_cidrs": cidrs[1:],
        "owner": owner or netname,
        "handle": handle,
        "rir": _rir_label(base),
        "fetched_at": _now().isoformat(),
        "source": "rdap",
    }


def _rir_label(base: str) -> str:
    """Short RIR name from its RDAP base URL (best-effort, for context only)."""
    for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
        if rir in base.lower():
            return rir
    return ""


def _classify(ip_str: str) -> dict | None:
    """Return a terminal record for non-global / malformed IPs, else None
    (meaning: needs an RDAP lookup)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"owner": "", "cidr": "", "handle": "", "rir": "", "source": "error"}
    if not ip.is_global:
        return {
            "owner": "private/reserved", "cidr": "", "handle": "",
            "rir": "", "source": "private",
        }
    return None


def _public(rec: dict) -> dict:
    """Project an internal cache record down to the public result shape."""
    return {
        "owner": rec.get("owner", ""),
        "cidr": rec.get("cidr", ""),
        "handle": rec.get("handle", ""),
        "rir": rec.get("rir", ""),
        "source": rec.get("source", ""),
    }


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def attribute_ips(
    ips: Iterable[str], *, refresh: bool = False, timeout: float = 5.0,
) -> dict[str, dict]:
    """Map each unique IP string to ``{owner, cidr, handle, rir, source}``.

    `source` is one of ``cache``, ``rdap``, ``private``, ``error``; `owner` is
    ``""`` when unknown. Private/reserved IPs and malformed strings never hit
    the network. RDAP misses are fetched (bounded concurrency), then persisted
    to the on-disk CIDR cache. `refresh=True` ignores cached blocks for the IPs
    in this call and refetches them.
    """
    unique = {ip for ip in ips if ip}
    results: dict[str, dict] = {}
    to_fetch: list[tuple[str, ipaddress._BaseAddress]] = []

    cache = _Cache()
    for ip_str in unique:
        terminal = _classify(ip_str)
        if terminal is not None:
            results[ip_str] = terminal
            continue
        ip = ipaddress.ip_address(ip_str)
        if not refresh:
            hit = cache.lookup(ip)
            if hit is not None and not _is_stale(hit.get("fetched_at"), _STALE_AFTER):
                results[ip_str] = dict(_public(hit), source="cache")
                continue
        to_fetch.append((ip_str, ip))

    if not to_fetch:
        return results

    _refresh_bootstrap(cache, timeout=timeout)

    def work(item: tuple[str, ipaddress._BaseAddress]) -> tuple[str, dict | None]:
        ip_str, ip = item
        base = _rdap_base_for(ip, cache)
        if not base:
            return ip_str, None
        return ip_str, _query_rdap(ip_str, ip, base, timeout=timeout)

    new_records: list[dict] = []
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        for ip_str, rec in pool.map(work, to_fetch):
            if rec is None:
                # No RIR mapping (e.g. bootstrap unavailable) — report, don't cache.
                results[ip_str] = {
                    "owner": "", "cidr": "", "handle": "", "rir": "",
                    "source": "error",
                }
                continue
            results[ip_str] = _public(rec)
            # Persist the primary block plus any sibling blocks for the same owner.
            extras = rec.pop("extra_cidrs", [])
            new_records.append(rec)
            for c in extras:
                new_records.append(dict(rec, cidr=c))

    if new_records:
        cache.add(new_records)
        cache.save()
    return results
