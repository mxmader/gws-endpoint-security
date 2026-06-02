#!/usr/bin/env python3
"""List Workspace users with their associated active Macs (FileVault status inline).

For each Workspace user, correlates against the survivor set produced by
`list_mac_devices.list_mac_devices(...)` — same default filter (active in
the trailing --last-sync-days, has a serial, deduped by serial). Sort
surfaces gaps first:

  1. Users with no Mac associated.
  2. Users with at least one Mac NOT in `ENCRYPTED` state.
  3. Users with all associated Macs `ENCRYPTED`.

Within each group, sort by primary email.

Matching is by email address: a user's `primaryEmail` and `aliases` are
intersected with each Mac's `userEmails` (the union of every email Cloud
Identity attributed to records sharing that serial). Case-insensitive.

Auth: keyless. Reuses `build_credentials` from list_mac_devices.py.
Requires the `admin.directory.user.readonly` scope in DWD and the Admin
API → Users (Read) privilege on WORKSPACE_ADMIN_EMAIL, in addition to
the Mac side's existing scope + privilege.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from list_mac_devices import (
    _execute,
    _format_plain,
    build_credentials,
    list_mac_devices,
    write_formatted,
)

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/cloud-identity.devices.readonly",
]


def fetch_users(svc, include_suspended: bool) -> list[dict]:
    """Paginated Admin SDK users.list. Trim payload with a fields mask."""
    out: list[dict] = []
    kwargs = dict(
        customer="my_customer",
        maxResults=500,
        fields=(
            "users(primaryEmail,aliases,suspended,lastLoginTime,name/fullName),"
            "nextPageToken"
        ),
    )
    if not include_suspended:
        kwargs["query"] = "isSuspended=false"
    req = svc.users().list(**kwargs)
    while req is not None:
        resp = _execute(req)
        out.extend(resp.get("users", []))
        req = svc.users().list_next(req, resp)
    return out


def correlate(users: list[dict], macs: list[dict]) -> list[dict]:
    """Attach `_macs` (list of survivor dicts) to each user via email match."""
    # Build address -> mac (one mac may appear under multiple addresses).
    mac_by_address: dict[str, list[dict]] = {}
    for m in macs:
        for ue in m.get("userEmails") or []:
            mac_by_address.setdefault(ue.lower(), []).append(m)

    rows: list[dict] = []
    for u in users:
        addresses = {(u.get("primaryEmail") or "").lower()}
        addresses.update(
            (a.get("alias") or "").lower()
            for a in (u.get("aliases") or [])
            if isinstance(a, dict)
        )
        addresses.discard("")
        # An alias entry can be a bare string in some discovery shapes; cover that.
        for a in u.get("aliases") or []:
            if isinstance(a, str):
                addresses.add(a.lower())

        seen_serials: set[str] = set()
        user_macs: list[dict] = []
        for addr in addresses:
            for m in mac_by_address.get(addr, []):
                serial = (m.get("serialNumber") or "").strip()
                if serial and serial in seen_serials:
                    continue
                seen_serials.add(serial)
                user_macs.append(m)

        rows.append({
            **u,
            "_macs": user_macs,
        })
    return rows


def _user_sort_key(row: dict) -> tuple:
    """Group users: no mac (0) -> any non-ENCRYPTED (1) -> all ENCRYPTED (2)."""
    macs = row.get("_macs") or []
    if not macs:
        group = 0
    elif any((m.get("encryptionState") or "").upper() != "ENCRYPTED" for m in macs):
        group = 1
    else:
        group = 2
    return (group, (row.get("primaryEmail") or "").lower())


def _format_macs_cell(macs: list[dict]) -> str:
    """`ENCRYPTED C02ZZ1 (MacBook Pro), NOT_ENCRYPTED C02ZZ2 (Mac16,6)` or `-`."""
    if not macs:
        return "-"
    parts: list[str] = []
    for m in macs:
        enc = (m.get("encryptionState") or "UNKNOWN").upper()
        serial = m.get("serialNumber") or "?"
        model = m.get("model") or "?"
        parts.append(f"{enc} {serial} ({model})")
    return ", ".join(parts)


def _table_columns(rows: list[dict]):
    """Build (headers, table_rows) for the user table. Shared across formats."""
    def row_tuple(r: dict) -> tuple:
        name = ((r.get("name") or {}).get("fullName") or "-")
        macs = r.get("_macs") or []
        return (
            r.get("primaryEmail") or "-",
            name,
            str(len(macs)),
            _format_macs_cell(macs),
            r.get("lastLoginTime") or "-",
        )

    headers = ("USER", "NAME", "MAC_COUNT", "MACS", "LAST_LOGIN")
    return headers, [row_tuple(r) for r in rows]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--last-sync-days", type=int, default=30,
        help="Mac-side filter: only correlate against Macs synced in the last N "
             "days (default: 30). Passed through to list_mac_devices.",
    )
    p.add_argument(
        "--include-suspended", action="store_true",
        help="Include suspended users (off by default; suspended users with no "
             "Mac are expected and would just be noise).",
    )
    p.add_argument(
        "--only-no-mac", action="store_true",
        help="Show only users with zero associated Macs.",
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
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Users (Read) + Mobile Device Management (Read) privileges>", file=sys.stderr)
        return 2

    timing: dict[str, float] = {}
    creds = build_credentials(sa_email, admin_email, SCOPES)
    t = time.perf_counter()
    creds.refresh(Request())
    timing["auth refresh"] = time.perf_counter() - t

    directory_svc = build(
        "admin", "directory_v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )

    # Parallel: Admin SDK users.list and the Cloud Identity Mac survivor scan.
    # They run against different APIs so there's no shared httplib2 instance.
    def _users():
        t0 = time.perf_counter()
        out = fetch_users(directory_svc, include_suspended=args.include_suspended)
        return out, time.perf_counter() - t0

    def _macs():
        t0 = time.perf_counter()
        out = list(list_mac_devices(
            creds,
            view="USER_ASSIGNED_DEVICES",
            with_clients=False,
            last_sync_days=args.last_sync_days,
            include_browser=False,
        ))
        return out, time.perf_counter() - t0

    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_users = pool.submit(_users)
        f_macs = pool.submit(_macs)
        users, users_elapsed = f_users.result()
        macs, macs_elapsed = f_macs.result()
    timing["[parallel] users.list"] = users_elapsed
    timing["[parallel] list_mac_devices"] = macs_elapsed
    timing["[parallel] section wall"] = time.perf_counter() - t

    rows = correlate(users, macs)
    if args.only_no_mac:
        rows = [r for r in rows if not r.get("_macs")]
    rows.sort(key=_user_sort_key)

    no_mac_n = sum(1 for r in rows if not r.get("_macs"))
    unenc_n = sum(
        1 for r in rows
        if r.get("_macs")
        and any((m.get("encryptionState") or "").upper() != "ENCRYPTED"
                for m in r["_macs"])
    )

    headers, table_rows = _table_columns(rows)
    plain_text = _format_plain(headers, table_rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(rows)} user(s): "
            f"{no_mac_n} with no Mac, {unenc_n} with at least one unencrypted Mac, "
            f"{len(rows) - no_mac_n - unenc_n} fully encrypted."
        )

    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=rows,
        csv_headers=headers,
        csv_rows=table_rows,
    )

    if args.timing:
        width = max(len(k) for k in timing) if timing else 0
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
