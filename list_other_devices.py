#!/usr/bin/env python3
"""List active devices that are NOT Mac, Android, or iOS — Windows, Linux, ChromeOS, etc.

The catch-all sibling of `list_mac_devices.py` and `list_mobile_devices.py`.
Anything Cloud Identity holds whose `deviceType` is none of MAC_OS / ANDROID /
IOS lands here: WINDOWS, LINUX, CHROME_OS, GOOGLE_SYNC (legacy ActiveSync mail
clients), and DEVICE_TYPE_UNSPECIFIED. Surfaces every such device that synced
within the trailing `--last-sync-days` (default 30), deduped to one row per
physical device (by serial when present, else by device id).

For this fleet — laptops and desktops — disk encryption is the headline risk
again, so rows are sorted the same way `list_mac_devices.py` sorts Macs:
encryption-undetermined first, then NOT_ENCRYPTED, then ENCRYPTED, with device
type as the secondary grouping so unencrypted Windows boxes don't hide behind
encrypted Chromebooks.

Auth: keyless. Reuses `build_credentials` from list_mac_devices.py and the
`cloud-identity.devices.readonly` scope — no new scope or DWD entry required.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from google.auth.transport.requests import Request

from list_mac_devices import (
    _format_plain,
    build_credentials,
    collect_devices,
    device_id_cell,
    encryption_sort_key,
    write_formatted,
)

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices.readonly"]

# deviceTypes this script deliberately excludes (handled by sibling scripts).
_EXCLUDED_TYPES = {"MAC_OS", "ANDROID", "IOS"}

_TYPE_LABEL = {
    "WINDOWS": "Windows",
    "LINUX": "Linux",
    "CHROME_OS": "ChromeOS",
    "GOOGLE_SYNC": "Google Sync",
    "DEVICE_TYPE_UNSPECIFIED": "unspecified",
}


def type_label(d: dict) -> str:
    dt = (d.get("deviceType") or "").upper()
    return _TYPE_LABEL.get(dt, dt or "?")


def other_sort_key(d: dict) -> tuple:
    """Encryption-risk first (reusing the Mac sort), then device type, user, serial."""
    group, primary_email, serial = encryption_sort_key(d)
    return (group, type_label(d), primary_email, serial)


def _table_columns(devices: list[dict]):
    """(headers, rows-as-tuples) for the other-devices table. Shared across formats."""
    def row(d: dict) -> tuple:
        return (
            ", ".join(d.get("userEmails") or []) or "-",
            device_id_cell(d),
            type_label(d),
            d.get("model") or "-",
            d.get("osVersion") or "-",
            d.get("encryptionState") or "-",
            d.get("hostname") or "-",
            d.get("ownerType") or "-",
            d.get("managementState") or "-",
            d.get("serialNumber") or "-",
            d.get("lastSyncTime") or "-",
        )

    headers = (
        "USER", "DEVICE_ID", "TYPE", "MODEL", "OS_VERSION", "ENCRYPTION",
        "HOSTNAME", "OWNER", "MGMT", "SERIAL", "LAST_SYNC",
    )
    return headers, [row(d) for d in devices]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--format", choices=["plain", "json", "csv"], default="plain",
        help="Output format (default: plain).",
    )
    p.add_argument(
        "--output", metavar="PATH",
        help="Write the formatted output to a file at PATH instead of stdout.",
    )
    p.add_argument(
        "--view",
        choices=["USER_ASSIGNED_DEVICES", "COMPANY_INVENTORY"],
        default="USER_ASSIGNED_DEVICES",
        help="Which device set to list (default: USER_ASSIGNED_DEVICES).",
    )
    p.add_argument(
        "--last-sync-days", type=int, default=30,
        help="Drop devices whose lastSyncTime is older than N days (default: 30).",
    )
    p.add_argument(
        "--require-serial", action="store_true",
        help="Drop records that report no serial number. Off by default.",
    )
    p.add_argument(
        "--user", metavar="EMAIL",
        help="Restrict to devices associated with a single user (by email). "
             "Skips the tenant-wide devices.list and issues one server-side "
             "email-filtered deviceUsers.list plus a batched devices.get on that "
             "user's device set — then keeps only the non-Mac/Android/iOS records.",
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
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Mobile Device Management read privilege>", file=sys.stderr)
        return 2

    timing: dict[str, float] = {}
    creds = build_credentials(sa_email, admin_email, SCOPES)
    t = time.perf_counter()
    creds.refresh(Request())
    timing["auth refresh"] = time.perf_counter() - t

    t = time.perf_counter()
    devices = collect_devices(
        creds,
        device_filter=lambda d: (d.get("deviceType") or "").upper() not in _EXCLUDED_TYPES,
        view=args.view,
        last_sync_days=args.last_sync_days,
        require_serial=args.require_serial,
        user_email=args.user,
    )
    timing["collect_devices"] = time.perf_counter() - t

    for d in devices:
        d["deviceTypeLabel"] = type_label(d)
    devices.sort(key=other_sort_key)

    # Bucket counts mirror the encryption sort groups (0..2).
    undetermined_n = not_enc_n = enc_n = 0
    for d in devices:
        if encryption_sort_key(d)[0] == 0:
            undetermined_n += 1
        elif encryption_sort_key(d)[0] == 1:
            not_enc_n += 1
        else:
            enc_n += 1
    by_type: dict[str, int] = {}
    for d in devices:
        by_type[type_label(d)] = by_type.get(type_label(d), 0) + 1
    type_breakdown = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items())) or "none"

    headers, rows = _table_columns(devices)
    plain_text = _format_plain(headers, rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(devices)} non-Mac/Android/iOS device(s) active "
            f"in the last {args.last_sync_days} day(s) ({type_breakdown}): "
            f"{undetermined_n} with undetermined encryption, "
            f"{not_enc_n} NOT_ENCRYPTED, {enc_n} ENCRYPTED."
        )

    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=devices,
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
