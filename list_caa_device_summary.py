#!/usr/bin/env python3
"""Context-Aware Access travel trace per device, for one user.

A concise companion to `list_caa_events.py`: instead of every CAA decision, it
collapses the `context_aware_access` log to **one row per unique (device id,
IP) pair** — the most recent event for each, regardless of access-level outcome
— so you can trace where each of a user's devices has recently appeared (its
distinct source IPs) with repeated same-IP events collapsed to a single line.

Scoped to one user (`--user`, required) over `--days`. Rows are grouped by
device, newest sighting first within each. Columns:
TIME, LOCAL_TIME, DEVICE_ID, MODEL, DEVICE_STATE, IP, IP_OWNER, LOCATION.

TIME is the raw UTC stamp; LOCAL_TIME renders it in `--tz` (an IANA zone, e.g.
'America/Denver') or the system local zone when omitted. IP / LOCATION come off
the CAA event's native `networkInfo` envelope; MODEL is resolved from the Cloud
Identity device record (Macs *and* iOS/Android); IP_OWNER is RDAP-resolved and
locally cached (`--no-ip-attribution` to skip).

Auth: keyless. Needs `admin.reports.audit.readonly` (CAA events) +
`cloud-identity.devices.readonly` (device records) in the DWD entry.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ip_attribution import attribute_ips
from list_caa_events import _param, build_device_catalog, fetch_caa_activity
from list_mac_devices import (
    _format_plain,
    build_credentials,
    decode_model,
    render_location,
    write_formatted,
)

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/cloud-identity.devices.readonly",
]


def latest_per_device_ip(activities) -> dict[tuple, dict]:
    """Most-recent CAA event per (device id, IP) pair across the activity stream.

    Keying on (device id, IP) keeps one row per distinct source IP a device was
    seen from — a deduped travel trace — versus a single row per device. Keeps
    the row with the greatest timestamp per pair (RFC 3339 sorts lexically). IP
    / networkInfo come off the activity envelope, the same place
    `list_signins.py` reads them.
    """
    latest: dict[tuple, dict] = {}
    for activity in activities:
        time_str = (activity.get("id") or {}).get("time") or ""
        ip = activity.get("ipAddress") or ""
        network_info = activity.get("networkInfo") or {}
        for ev in activity.get("events") or []:
            device_id = _param(ev, "CAA_DEVICE_ID")
            if not device_id:
                continue
            key = (device_id, ip)
            cur = latest.get(key)
            if cur is None or time_str > cur["time"]:
                latest[key] = {
                    "time": time_str,
                    "device_id": device_id,
                    "device_state": _param(ev, "CAA_DEVICE_STATE"),
                    "ip": ip,
                    "location": render_location(network_info),
                }
    return latest


def to_local(ts: str, tz: ZoneInfo | None) -> str:
    """RFC 3339 UTC timestamp -> 'YYYY-MM-DD HH:MM:SS TZ' in `tz`, or the
    system local zone when `tz` is None. Returns the raw string if unparseable.
    """
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")


HEADERS = (
    "TIME", "LOCAL_TIME", "DEVICE_ID", "MODEL", "DEVICE_STATE",
    "IP", "IP_OWNER", "LOCATION",
)


def _table_columns(rows: list[dict]) -> list[tuple]:
    return [
        (
            r.get("time") or "-",
            r.get("local_time") or "-",
            r.get("device_id") or "-",
            r.get("model") or "-",
            r.get("device_state") or "-",
            r.get("ip") or "-",
            r.get("ip_owner") or "-",
            r.get("location") or "-",
        )
        for r in rows
    ]


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--user", required=True, metavar="EMAIL",
        help="Required. User whose CAA events to summarize.",
    )
    p.add_argument(
        "--days", type=int, default=7,
        help="Lookback window in days (default: 7). Reports API retention ~6mo.",
    )
    p.add_argument(
        "--no-ip-attribution", action="store_true",
        help="Skip IP_OWNER enrichment (no RDAP lookups).",
    )
    p.add_argument(
        "--tz", metavar="ZONE",
        help="IANA timezone for the LOCAL_TIME column (e.g. 'America/Denver'). "
             "Defaults to the system local timezone.",
    )
    p.add_argument(
        "--format", choices=["plain", "json", "csv"], default="plain",
        help="Output format (default: plain).",
    )
    p.add_argument(
        "--output", metavar="PATH",
        help="Write the formatted output to a file at PATH instead of stdout.",
    )
    args = p.parse_args()

    tz: ZoneInfo | None = None
    if args.tz:
        try:
            tz = ZoneInfo(args.tz)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            print(f"Invalid --tz '{args.tz}': {exc}", file=sys.stderr)
            return 2

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Reports (Read) + Mobile Device Management (Read)>", file=sys.stderr)
        return 2

    start_time = (
        datetime.now(timezone.utc) - timedelta(days=args.days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    creds = build_credentials(sa_email, admin_email, SCOPES)
    activities = fetch_caa_activity(creds, start_time, args.user)
    rows = list(latest_per_device_ip(activities).values())
    for r in rows:
        r["local_time"] = to_local(r["time"], tz)

    # Resolve each device id to a model via the Cloud Identity catalog
    # (user-scoped). type_filter=None so iOS/Android records are included too,
    # not just Macs — their model comes straight off the device record.
    catalog = build_device_catalog(creds, user_email=args.user, type_filter=None)
    for r in rows:
        dev = catalog.get(r["device_id"]) or {}
        r["model"] = decode_model(dev.get("model")) or dev.get("model") or ""

    if args.no_ip_attribution:
        for r in rows:
            r["ip_owner"] = ""
    else:
        attribution = attribute_ips(r["ip"] for r in rows)
        for r in rows:
            info = attribution.get(r["ip"]) if r.get("ip") else None
            r["ip_owner"] = (info or {}).get("owner", "")

    # Group by device, newest sighting first within each (stable two-pass:
    # time desc, then device id — so a device's IP hops read as a travel log).
    rows.sort(key=lambda r: r.get("time") or "", reverse=True)
    rows.sort(key=lambda r: r.get("device_id") or "")

    plain_text = _format_plain(HEADERS, _table_columns(rows))
    if args.format == "plain" and not args.output:
        ndev = len({r["device_id"] for r in rows})
        plain_text = (
            f"{plain_text}\n\n{len(rows)} device/IP sighting(s) across {ndev} "
            f"device(s) for {args.user} in the last {args.days} day(s)."
        )
    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=rows,
        csv_headers=HEADERS,
        csv_rows=_table_columns(rows),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
