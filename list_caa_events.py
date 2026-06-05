#!/usr/bin/env python3
"""List Context-Aware Access events correlated with device records.

Reads the Admin SDK Reports `context_aware_access` activity log and surfaces
events where a named access level appears in either CAA_ACCESS_LEVEL_SATISFIED
or CAA_ACCESS_LEVEL_UNSATISFIED. Each row is joined against the matching
Cloud Identity Device record (when CAA_DEVICE_ID resolves), adding the same
columns `list_mac_devices.py` produces — SIGNALS, SERIAL, MODEL (decoded via
mac_models.json), OS_VERSION, HOSTNAME, ASSET_TAG, ENCRYPTION, LAST_SYNC.

The access attempt's own network context comes off the activity envelope (the
same place `list_signins.py` reads it on the `login` log): IP (raw `ipAddress`),
IP_ASN (Google's native ASN + region from `networkInfo`), LOCATION (that
decoded to "Subdivision, Country"), and IP_OWNER (RDAP-resolved network owner,
cached locally — see `ip_attribution.py`; `--no-ip-attribution` skips it). This
is what ties a denied device to the IP/location it was denied from, in one log.

OUTCOME column values:

- `satisfied` — the named access level passed at decision time. The denial
  was caused by some *other* policy condition failing.
- `unsatisfied` — the named access level was the failing condition.

CAA_DEVICE_ID format note: the value matches the Cloud Identity Device
resource's `deviceId` field, which is distinct from its `name` (resource
path). The script enumerates Mac devices once up front (scoped to one user
when `--user` is set, full tenant otherwise) and joins CAA events to that
catalog by `deviceId` dict lookup — no per-event API call needed. Events
whose `CAA_DEVICE_ID` doesn't appear in the catalog (different origin: a
non-Mac device, a deleted Mac, or a user-scoped run that doesn't include
the device) land with empty device columns.

Auth: keyless. Uses both `admin.reports.audit.readonly` (CAA events) and
`cloud-identity.devices.readonly` (device records). Both scopes must be in
the DWD entry; the admin role needs Reports (Read) + Mobile Device Management
(Read).
"""
from __future__ import annotations

import time
_T_MODULE_START = time.perf_counter()

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable

from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ip_attribution import attribute_ips
from list_mac_devices import (
    _execute,
    _format_plain,
    _run_batch,
    build_credentials,
    classify_signals,
    decode_model,
    fetch_user_device_users,
    render_ip_asn,
    render_location,
    write_formatted,
)

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/cloud-identity.devices.readonly",
]


def _param(event: dict, name: str) -> str:
    for p in event.get("parameters") or []:
        if p.get("name") == name:
            v = p.get("value")
            if v is None and p.get("boolValue") is not None:
                v = "true" if p["boolValue"] else "false"
            return v or ""
    return ""


def _param_list(event: dict, name: str) -> list[str]:
    for p in event.get("parameters") or []:
        if p.get("name") == name:
            return list(p.get("multiValue") or [])
    return []


def fetch_caa_activity(
    creds, start_time: str, user_key: str, *, page_log: list[float] | None = None,
):
    """Paginated activities.list against the `context_aware_access` app log."""
    svc = build(
        "admin", "reports_v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )
    req = svc.activities().list(
        userKey=user_key,
        applicationName="context_aware_access",
        startTime=start_time,
        maxResults=1000,
    )
    while req is not None:
        t0 = time.perf_counter()
        resp = _execute(req)
        if page_log is not None:
            page_log.append(time.perf_counter() - t0)
        for item in resp.get("items", []):
            yield item
        req = svc.activities().list_next(req, resp)


def flatten(
    activities,
    access_level: str,
    *,
    satisfied_only: bool,
    unsatisfied_only: bool,
) -> list[dict]:
    """One row per (activity, event) matching the access-level filter."""
    rows: list[dict] = []
    for activity in activities:
        user = (activity.get("actor") or {}).get("email") or ""
        time_str = (activity.get("id") or {}).get("time") or ""
        # IP / network are on the activity envelope (same place list_signins.py
        # reads them off the `login` log), not in the per-event parameters.
        ip = activity.get("ipAddress") or ""
        network_info = activity.get("networkInfo") or {}
        for ev in activity.get("events") or []:
            satisfied = _param_list(ev, "CAA_ACCESS_LEVEL_SATISFIED")
            unsatisfied = _param_list(ev, "CAA_ACCESS_LEVEL_UNSATISFIED")
            in_satisfied = access_level in satisfied
            in_unsatisfied = access_level in unsatisfied
            if not (in_satisfied or in_unsatisfied):
                continue
            # If the level somehow shows in both lists, "unsatisfied" is the
            # more interesting attribution (the level *did* fail somewhere).
            outcome = "unsatisfied" if in_unsatisfied else "satisfied"
            if satisfied_only and outcome != "satisfied":
                continue
            if unsatisfied_only and outcome != "unsatisfied":
                continue
            # DEVICE_RISKS may be named either CAA_DEVICE_RISKS or DEVICE_RISKS
            # in the parameters list — try both before giving up.
            device_risks = (
                _param_list(ev, "CAA_DEVICE_RISKS")
                or _param_list(ev, "DEVICE_RISKS")
            )
            rows.append({
                "time": time_str,
                "user": user,
                "device_id": _param(ev, "CAA_DEVICE_ID"),
                "app": _param(ev, "CAA_APPLICATION"),
                # "protected API access" parameter — try both candidate
                # names (Google's appendix and the Investigation Tool UI
                # don't agree on the casing/prefix).
                "protected_api": (
                    _param(ev, "PROTECTED_API_ACCESS")
                    or _param(ev, "CAA_PROTECTED_API_ACCESS")
                ),
                "device_state": _param(ev, "CAA_DEVICE_STATE"),
                "device_risks": device_risks,
                "outcome": outcome,
                "ip": ip,
                "ip_asn": render_ip_asn(network_info),
                "location": render_location(network_info),
                "event_name": ev.get("name") or "",
            })
    return rows


_DEVICE_FIELDS = (
    "name,deviceId,serialNumber,lastSyncTime,model,osVersion,"
    "assetTag,encryptionState,hostname,deviceType"
)


def build_device_catalog(
    creds, user_email: str | None = None, *, debug: bool = False,
) -> dict[str, dict]:
    """Build `{deviceId: device_record}` for CAA-event correlation.

    The Cloud Identity Device resource carries two identifiers:
      - `name`: the resource path (`devices/{opaque}`) used by devices.get
      - `deviceId`: the EV-style identifier (43-char base64url) emitted by
        the CAA event log as `CAA_DEVICE_ID`
    Joining CAA events to Device records is a `deviceId` dict lookup, NOT a
    `devices.get(name=<caa_id>)` call (the latter 400s, since CAA IDs aren't
    valid resource paths).

    Scoping:
      - `user_email=None`: enumerate all Mac devices in the tenant via
        `devices.list(filter=type:mac)`.
      - `user_email=...`: scope to that user's devices via the focused path
        (bulk deviceUsers.list + filter, then batched devices.get on the
        resulting device names). Matches the `--user` mode in
        list_mac_devices.py.

    Either way, the returned map is keyed by `deviceId` so the caller's
    per-event lookup is O(1) with no additional API calls.
    """
    svc = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )

    devices: list[dict] = []
    if user_email:
        users_by_device, _ = fetch_user_device_users(svc, user_email)
        device_names = [f"devices/{did}" for did in users_by_device.keys()]
        if device_names:
            factories: dict[str, Callable[[], object]] = {
                f"d{i}": (
                    lambda nm=name: svc.devices().get(
                        name=nm, customer="customers/my_customer",
                    )
                )
                for i, name in enumerate(device_names)
            }
            responses = _run_batch(svc, factories, ignore_statuses={400, 404})
            devices = [resp for resp in responses.values() if resp]
    else:
        req = svc.devices().list(
            customer="customers/my_customer",
            filter="type:mac",
            view="USER_ASSIGNED_DEVICES",
            fields=f"devices({_DEVICE_FIELDS}),nextPageToken",
        )
        while req is not None:
            resp = _execute(req)
            devices.extend(resp.get("devices", []))
            req = svc.devices().list_next(req, resp)

    catalog = {d["deviceId"]: d for d in devices if d.get("deviceId")}
    if debug:
        print(
            f"[debug] device catalog: {len(catalog)} entries "
            f"({'user-scoped' if user_email else 'tenant-wide Macs'})",
            file=sys.stderr,
        )
    return catalog


def attach_device_fields(rows: list[dict], device_by_id: dict[str, dict]) -> None:
    """Stamp flat device_* fields onto each row (empty when no match)."""
    blank_keys = (
        "device_signals", "device_serial", "device_model",
        "device_os_version", "device_hostname", "device_asset_tag",
        "device_encryption", "device_last_sync",
    )
    for r in rows:
        did = r.get("device_id") or ""
        device = device_by_id.get(did) if did else None
        if not device:
            for k in blank_keys:
                r[k] = ""
            continue
        r["device_signals"] = classify_signals(device)
        r["device_serial"] = device.get("serialNumber") or ""
        r["device_model"] = (
            decode_model(device.get("model")) or device.get("model") or ""
        )
        r["device_os_version"] = device.get("osVersion") or ""
        r["device_hostname"] = device.get("hostname") or ""
        r["device_asset_tag"] = device.get("assetTag") or ""
        r["device_encryption"] = device.get("encryptionState") or ""
        r["device_last_sync"] = device.get("lastSyncTime") or ""


HEADERS = (
    "TIME", "USER", "DEVICE_ID", "APP", "PROTECTED_API", "DEVICE_STATE",
    "DEVICE_RISKS", "OUTCOME",
    "IP", "IP_ASN", "LOCATION", "IP_OWNER",
    "SIGNALS", "SERIAL", "MODEL", "OS_VERSION", "HOSTNAME", "ASSET_TAG",
    "ENCRYPTION", "LAST_SYNC",
)


def _table_columns(rows: list[dict]) -> list[tuple]:
    """Full-data row tuples (no truncation). Used for CSV + as input to plain."""
    out: list[tuple] = []
    for r in rows:
        out.append((
            r.get("time") or "-",
            r.get("user") or "-",
            r.get("device_id") or "-",
            r.get("app") or "-",
            r.get("protected_api") or "-",
            r.get("device_state") or "-",
            ", ".join(r.get("device_risks") or []) or "-",
            r.get("outcome") or "-",
            r.get("ip") or "-",
            r.get("ip_asn") or "-",
            r.get("location") or "-",
            r.get("ip_owner") or "-",
            r.get("device_signals") or "-",
            r.get("device_serial") or "-",
            r.get("device_model") or "-",
            r.get("device_os_version") or "-",
            r.get("device_hostname") or "-",
            r.get("device_asset_tag") or "-",
            r.get("device_encryption") or "-",
            r.get("device_last_sync") or "-",
        ))
    return out


def render_table(rows: list[dict]) -> str:
    """Plain-table rendering with terminal-width truncation on the long columns."""
    def shrink(s: str, limit: int) -> str:
        return s if len(s) <= limit else s[: limit - 1] + "…"

    full = _table_columns(rows)
    trimmed = [
        (
            r[0],                # TIME
            r[1],                # USER
            r[2],                # DEVICE_ID (full width — useful for debugging)
            r[3],                # APP (full width)
            shrink(r[4], 50),    # PROTECTED_API
            r[5],                # DEVICE_STATE
            shrink(r[6], 40),    # DEVICE_RISKS
            r[7],                # OUTCOME
            shrink(r[8], 39),    # IP (IPv6 max width)
            r[9],                # IP_ASN
            shrink(r[10], 30),   # LOCATION
            shrink(r[11], 30),   # IP_OWNER
            r[12],               # SIGNALS
            r[13],               # SERIAL
            shrink(r[14], 40),   # MODEL (decoded names can run long)
            r[15], r[16], r[17], r[18], r[19],
        )
        for r in full
    ]
    return _format_plain(HEADERS, trimmed)


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--access-level", required=True, metavar="NAME",
        help="Required. Name of the access level to filter by. The script "
             "keeps events where this name appears in either the "
             "CAA_ACCESS_LEVEL_SATISFIED or CAA_ACCESS_LEVEL_UNSATISFIED "
             "list on the event.",
    )

    outcome_group = p.add_mutually_exclusive_group()
    outcome_group.add_argument(
        "--satisfied-only", action="store_true",
        help="Show only events where the access level was in the SATISFIED "
             "list (it passed; another condition caused the denial).",
    )
    outcome_group.add_argument(
        "--unsatisfied-only", action="store_true",
        help="Show only events where the access level was in the "
             "UNSATISFIED list (it was the failing condition).",
    )

    time_group = p.add_mutually_exclusive_group()
    time_group.add_argument(
        "--days", type=int, default=7,
        help="Lookback window in days (default: 7). Reports API retention is "
             "~6 months.",
    )
    time_group.add_argument(
        "--since", metavar="RFC3339",
        help="Explicit cutover timestamp (e.g. '2026-06-01T00:00:00Z'). "
             "Overrides --days when set.",
    )

    p.add_argument(
        "--user", metavar="EMAIL",
        help="Restrict to a single user's events (passed through as "
             "userKey for server-side scoping).",
    )
    p.add_argument(
        "--format", choices=["plain", "json", "csv"], default="plain",
        help="Output format (default: plain).",
    )
    p.add_argument(
        "--output", metavar="PATH",
        help="Write the formatted output to a file at PATH instead of stdout.",
    )
    p.add_argument(
        "--timing", action="store_true",
        help="Print a per-phase wall-clock breakdown to stderr.",
    )
    p.add_argument(
        "--debug", action="store_true",
        help="Log device-catalog size to stderr (counts entries that were "
             "available for CAA event correlation).",
    )
    p.add_argument(
        "--no-ip-attribution", action="store_true",
        help="Skip IP_OWNER enrichment (no RDAP lookups). IP / IP_ASN / "
             "LOCATION still populate from the event's native networkInfo.",
    )
    p.add_argument(
        "--refresh-ip-attribution", action="store_true",
        help="Bypass the cached owner for IPs seen this run and refetch them "
             "from RDAP.",
    )
    args = p.parse_args()

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Reports (Read) + Mobile Device Management (Read)>", file=sys.stderr)
        return 2

    if args.since:
        start_time = args.since
    else:
        start_time = (
            datetime.now(timezone.utc) - timedelta(days=args.days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    timing: dict[str, float] = {}
    page_log: list[float] = []
    if args.timing:
        timing["module import (post 'import time')"] = (
            time.perf_counter() - _T_MODULE_START
        )

    t = time.perf_counter()
    creds = build_credentials(sa_email, admin_email, SCOPES)
    if args.timing:
        timing["build_credentials (local)"] = time.perf_counter() - t

    t = time.perf_counter()
    creds.refresh(Request())
    if args.timing:
        timing["auth refresh (signJwt + token)"] = time.perf_counter() - t

    t = time.perf_counter()
    activities = fetch_caa_activity(
        creds, start_time, args.user or "all",
        page_log=page_log if args.timing else None,
    )
    rows = flatten(
        activities,
        args.access_level,
        satisfied_only=args.satisfied_only,
        unsatisfied_only=args.unsatisfied_only,
    )
    if args.timing:
        timing[f"activities.list + filter (pages={len(page_log)}, rows={len(rows)})"] = (
            time.perf_counter() - t
        )

    t = time.perf_counter()
    device_by_id = build_device_catalog(
        creds, user_email=args.user, debug=args.debug,
    )
    if args.timing:
        timing[f"device catalog ({'user-scoped' if args.user else 'tenant-wide'}, n={len(device_by_id)})"] = (
            time.perf_counter() - t
        )

    attach_device_fields(rows, device_by_id)

    # Annotate each row's IP with its registered network owner (IP_OWNER).
    # IP / IP_ASN / LOCATION already came off the event's native networkInfo.
    t = time.perf_counter()
    if args.no_ip_attribution:
        for r in rows:
            r["ip_owner"] = ""
            r["ip_attribution"] = None
    else:
        attribution = attribute_ips(
            (r.get("ip") for r in rows),
            refresh=args.refresh_ip_attribution,
        )
        for r in rows:
            info = attribution.get(r["ip"]) if r.get("ip") else None
            r["ip_owner"] = (info or {}).get("owner", "")
            r["ip_attribution"] = info
    if args.timing:
        timing["ip attribution (RDAP, cached)"] = time.perf_counter() - t

    rows.sort(key=lambda r: r.get("time") or "", reverse=True)

    plain_text = render_table(rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(rows)} CAA event(s) involving access level "
            f"'{args.access_level}' since {start_time}."
        )

    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=rows,
        csv_headers=HEADERS,
        csv_rows=_table_columns(rows),
    )

    if args.timing:
        wall = time.perf_counter() - _T_MODULE_START
        width = max(len(k) for k in timing) if timing else 0
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
        if page_log:
            print(
                f"  per-page latency: n={len(page_log)} "
                f"min={min(page_log)*1000:.0f}ms max={max(page_log)*1000:.0f}ms "
                f"avg={(sum(page_log)/len(page_log))*1000:.0f}ms "
                f"total={sum(page_log)*1000:.0f}ms",
                file=sys.stderr,
            )
        print(f"  wall (post import time): {wall*1000:8.1f} ms", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
