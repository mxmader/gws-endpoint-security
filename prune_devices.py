#!/usr/bin/env python3
"""Delete stale and unidentifiable device records from Cloud Identity.

Two deletion rules (OR'd — either triggers a delete):

1. Any device with `deviceType == MAC_OS` whose `lastSyncTime` is older
   than --last-sync-days N (default 30). Missing/unparseable sync times
   count as infinitely stale.
2. Any device (any type) with an empty/missing `serialNumber`.

Dry-run is the default. Plain invocation prints the candidate set and
exits without modifying anything. Pass --execute to actually call
`devices.delete` on each candidate.

Auth: keyless. Reuses `build_credentials` from list_mac_devices.py. The
write scope `cloud-identity.devices` (no `.readonly`) must be present in
the DWD entry, and WORKSPACE_ADMIN_EMAIL must hold the full Mobile
Device Management privilege (not Read-only).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable

from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from list_mac_devices import (
    _device_id,
    _execute,
    _format_plain,
    _parse_sync,
    _run_batch,
    build_credentials,
    fetch_mac_device_users,
    write_formatted,
)

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices"]

# Cloud Identity returns 404 for already-deleted devices. Treat as success.
_IDEMPOTENT_DELETE_STATUSES = frozenset({404})


def list_all_devices(svc) -> list[dict]:
    """Enumerate every Device in the tenant (any type). One paginated call."""
    out: list[dict] = []
    req = svc.devices().list(
        customer="customers/my_customer",
        fields=(
            "devices(name,deviceType,serialNumber,lastSyncTime,model,ownerType),"
            "nextPageToken"
        ),
    )
    while req is not None:
        resp = _execute(req)
        out.extend(resp.get("devices", []))
        req = svc.devices().list_next(req, resp)
    return out


def classify(d: dict, cutoff: datetime) -> list[str]:
    """Return the list of rule names this device triggers (empty = keep)."""
    reasons: list[str] = []
    device_type = (d.get("deviceType") or "").upper()
    if device_type == "MAC_OS":
        sync = _parse_sync(d)
        if sync is None or sync < cutoff:
            reasons.append("stale mac")
    if not (d.get("serialNumber") or "").strip():
        reasons.append("no serial")
    return reasons


def _table_columns(candidates: list[dict]):
    """Build (headers, rows) for the candidate table. Shared across formats."""
    def row(d: dict) -> tuple:
        return (
            ", ".join(d.get("userEmails") or []) or "-",
            d.get("deviceType") or "-",
            d.get("serialNumber") or "-",
            d.get("model") or "-",
            d.get("lastSyncTime") or "-",
            ", ".join(d.get("_reasons") or []) or "-",
        )

    headers = ("USER", "TYPE", "SERIAL", "MODEL", "LAST_SYNC", "REASON")
    rows = [row(d) for d in candidates]
    return headers, rows


def _delete_candidates(svc, candidates: list[dict]) -> int:
    """Batched devices.delete with 404-idempotent + 429 retry. Returns delete count."""
    if not candidates:
        return 0
    factories: dict[str, Callable[[], object]] = {
        f"d{i}": (
            lambda nm=d["name"]: svc.devices().delete(
                name=nm, customer="customers/my_customer",
            )
        )
        for i, d in enumerate(candidates)
    }
    results = _run_batch(svc, factories, ignore_statuses=_IDEMPOTENT_DELETE_STATUSES)
    return len(results)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--last-sync-days", type=int, default=30,
        help="Threshold for the 'stale Mac' rule (default: 30).",
    )
    p.add_argument(
        "--execute", action="store_true",
        help="Actually issue the deletes. Default is dry-run (print candidates only).",
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
        help="Print a per-phase wall-clock breakdown to stderr after the run.",
    )
    args = p.parse_args()

    if args.last_sync_days < 1:
        print("--last-sync-days must be >= 1", file=sys.stderr)
        return 2

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Mobile Device Management privilege>", file=sys.stderr)
        return 2

    timing: dict[str, float] = {}
    creds = build_credentials(sa_email, admin_email, SCOPES)
    t = time.perf_counter()
    creds.refresh(Request())
    timing["auth refresh"] = time.perf_counter() - t

    svc = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )
    svc2 = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )

    # Run devices.list and bulk deviceUsers.list in parallel — the second is
    # only used to attribute user emails to candidate rows, but it's
    # independent of the device enumeration.
    def _list_devices():
        t0 = time.perf_counter()
        out = list_all_devices(svc)
        return out, time.perf_counter() - t0

    def _list_users():
        t0 = time.perf_counter()
        out = fetch_mac_device_users(svc2)
        return out, time.perf_counter() - t0

    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_devs = pool.submit(_list_devices)
        f_users = pool.submit(_list_users)
        devices, dev_elapsed = f_devs.result()
        users_by_device, users_elapsed = f_users.result()
    timing["[parallel] devices.list"] = dev_elapsed
    timing["[parallel] deviceUsers.list (mac)"] = users_elapsed
    timing["[parallel] section wall"] = time.perf_counter() - t

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.last_sync_days)
    candidates: list[dict] = []
    stale_count = no_serial_count = 0
    for d in devices:
        reasons = classify(d, cutoff)
        if not reasons:
            continue
        d["_reasons"] = reasons
        device_users = users_by_device.get(_device_id(d.get("name", "")), [])
        d["userEmails"] = list({u.get("userEmail") for u in device_users if u.get("userEmail")})
        candidates.append(d)
        if "stale mac" in reasons:
            stale_count += 1
        if "no serial" in reasons:
            no_serial_count += 1

    deleted = 0
    if args.execute and candidates:
        t = time.perf_counter()
        deleted = _delete_candidates(svc, candidates)
        timing["devices.delete batched"] = time.perf_counter() - t

    headers, rows = _table_columns(candidates)
    plain_text = _format_plain(headers, rows)
    if args.format == "plain" and not args.output:
        if args.execute:
            footer = (
                f"\n\n{deleted} of {len(candidates)} candidate(s) deleted. "
                f"Cloud Identity processes deletes asynchronously — re-run to verify."
            )
        else:
            footer = (
                f"\n\nDRY RUN. {len(candidates)} candidate(s): "
                f"{stale_count} stale mac, {no_serial_count} no serial "
                f"({len(candidates) - max(stale_count, no_serial_count)} hit by both rules). "
                f"Re-run with --execute to delete."
            )
        plain_text = plain_text + footer

    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=candidates,
        csv_headers=headers,
        csv_rows=rows,
    )

    if args.timing:
        width = max(len(k) for k in timing) if timing else 0
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
