#!/usr/bin/env python3
"""List active Android and iOS devices in the Workspace tenant with posture signals.

The mobile sibling of `list_mac_devices.py`. Surfaces every Android/iOS device
that has synced within the trailing `--last-sync-days` (default 30), deduped to
one row per physical device (by serial when present, else by device id). Unlike
the Mac report — where FileVault status is the headline risk — the headline for
mobile is **device integrity**: a rooted/jailbroken device (`compromisedState ==
COMPROMISED`), then anything else carrying a risk flag (USB debugging, developer
options, sideloading from unknown sources, failed Play Integrity / SafetyNet,
potentially-harmful apps), then clean devices. Encryption is shown as a column
but does not drive the sort: iOS is always hardware-encrypted and modern Android
is encrypted by default, so encryption gaps are rarely the interesting signal
here.

Auth: keyless. Reuses `build_credentials` from list_mac_devices.py and the
`cloud-identity.devices.readonly` scope — no new scope or DWD entry required
beyond what `list_mac_devices.py` already needs.
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
    write_formatted,
)

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices.readonly"]

_PLATFORM = {"ANDROID": "Android", "IOS": "iOS"}


def platform_label(d: dict) -> str:
    dt = (d.get("deviceType") or "").upper()
    return _PLATFORM.get(dt, dt or "?")


def risk_flags(d: dict) -> list[str]:
    """Short tokens for the per-device risk signals present in this record.

    Booleans absent from the record (e.g. SafetyNet/Play Integrity fields on
    iOS, which never report them) are simply not flagged — we only flag a
    posture problem when the API explicitly says so.
    """
    flags: list[str] = []
    if (d.get("compromisedState") or "").upper() == "COMPROMISED":
        flags.append("compromised")
    aa = d.get("androidSpecificAttributes") or {}
    if aa.get("hasPotentiallyHarmfulApps"):
        flags.append("harmful-apps")
    if aa.get("ctsProfileMatch") is False:
        flags.append("cts-fail")
    if aa.get("verifiedBoot") is False:
        flags.append("no-verified-boot")
    if aa.get("verifyAppsEnabled") is False:
        flags.append("verify-apps-off")
    if aa.get("enabledUnknownSources"):
        flags.append("unknown-sources")
    if d.get("enabledDeveloperOptions"):
        flags.append("dev-options")
    if d.get("enabledUsbDebugging"):
        flags.append("usb-debug")
    return flags


def _risk_group(flags: list[str]) -> int:
    """0 = compromised (rooted/jailbroken), 1 = other risk flag(s), 2 = clean."""
    if "compromised" in flags:
        return 0
    return 1 if flags else 2


def mobile_sort_key(d: dict) -> tuple:
    """Riskiest devices first: compromised, then flagged, then clean.

    Within each group: by platform, then primary user email, then serial.
    """
    group = _risk_group(d.get("riskFlags") or [])
    emails = d.get("userEmails") or []
    primary_email = emails[0] if emails else ""
    serial = d.get("serialNumber") or ""
    return (group, platform_label(d), primary_email, serial)


def _compromised_cell(d: dict) -> str:
    state = (d.get("compromisedState") or "").upper()
    if state == "COMPROMISED":
        return "COMPROMISED"
    if state == "UNCOMPROMISED":
        return "clean"
    return "-"


def _table_columns(devices: list[dict]):
    """(headers, rows-as-tuples) for the mobile table. Shared across formats."""
    def row(d: dict) -> tuple:
        return (
            ", ".join(d.get("userEmails") or []) or "-",
            platform_label(d),
            d.get("model") or "-",
            d.get("osVersion") or "-",
            _compromised_cell(d),
            d.get("encryptionState") or "-",
            ", ".join(d.get("riskFlags") or []) or "-",
            d.get("ownerType") or "-",
            d.get("managementState") or "-",
            d.get("serialNumber") or "-",
            d.get("lastSyncTime") or "-",
        )

    headers = (
        "USER", "PLATFORM", "MODEL", "OS_VERSION", "COMPROMISED", "ENCRYPTION",
        "RISK_FLAGS", "OWNER", "MGMT", "SERIAL", "LAST_SYNC",
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
        help="Drop records that report no serial number (BYOD iOS often omits "
             "it). Off by default — for mobile, the device id is a fine identity "
             "key and a missing serial isn't itself a red flag.",
    )
    p.add_argument(
        "--user", metavar="EMAIL",
        help="Restrict to devices associated with a single user (by email). "
             "Skips the tenant-wide devices.list and issues one server-side "
             "email-filtered deviceUsers.list plus a batched devices.get on that "
             "user's device set — then keeps only the Android/iOS records.",
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
        device_filter=lambda d: (d.get("deviceType") or "").upper() in ("ANDROID", "IOS"),
        view=args.view,
        last_sync_days=args.last_sync_days,
        require_serial=args.require_serial,
        user_type_filters=["android", "ios"],
        user_email=args.user,
    )
    timing["collect_devices"] = time.perf_counter() - t

    # Enrich for display + JSON, then sort riskiest-first.
    for d in devices:
        d["platform"] = platform_label(d)
        d["riskFlags"] = risk_flags(d)
    devices.sort(key=mobile_sort_key)

    compromised_n = other_flagged_n = clean_n = 0
    for d in devices:
        g = _risk_group(d.get("riskFlags") or [])
        if g == 0:
            compromised_n += 1
        elif g == 1:
            other_flagged_n += 1
        else:
            clean_n += 1
    android_n = sum(1 for d in devices if (d.get("deviceType") or "").upper() == "ANDROID")
    ios_n = sum(1 for d in devices if (d.get("deviceType") or "").upper() == "IOS")

    headers, rows = _table_columns(devices)
    plain_text = _format_plain(headers, rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(devices)} mobile device(s) active in the last "
            f"{args.last_sync_days} day(s) ({android_n} Android, {ios_n} iOS): "
            f"{compromised_n} compromised, {other_flagged_n} with other risk "
            f"flags, {clean_n} clean."
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
