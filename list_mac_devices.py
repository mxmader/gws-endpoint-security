#!/usr/bin/env python3
"""List all MAC_OS devices in the Workspace tenant with their encryption status.

Auth: keyless. Uses your local gcloud ADC + the IAM signJwt API to mint a
domain-wide-delegated access token impersonating WORKSPACE_ADMIN_EMAIL.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import google.auth
from google.auth import iam
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPE = "https://www.googleapis.com/auth/cloud-identity.devices.readonly"


def build_credentials(sa_email: str, admin_email: str) -> service_account.Credentials:
    source_creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/iam"],
    )
    signer = iam.Signer(Request(), source_creds, sa_email)
    return service_account.Credentials(
        signer=signer,
        service_account_email=sa_email,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=[SCOPE],
        subject=admin_email,
    )


def _device_id(resource_name: str) -> str:
    # resource_name is "devices/{deviceId}" or "devices/{deviceId}/deviceUsers/{...}"
    parts = resource_name.split("/")
    return parts[1] if len(parts) >= 2 and parts[0] == "devices" else ""


def fetch_mac_user_emails(svc) -> dict[str, list[str]]:
    """deviceId -> [userEmail, ...] for every Mac DeviceUser, in one paginated pass."""
    by_device: dict[str, list[str]] = {}
    req = svc.devices().deviceUsers().list(
        parent="devices/-",
        customer="customers/my_customer",
        filter="type:mac",
    )
    while req is not None:
        resp = req.execute()
        for du in resp.get("deviceUsers", []):
            email = du.get("userEmail")
            if not email:
                continue
            by_device.setdefault(_device_id(du.get("name", "")), []).append(email)
        req = svc.devices().deviceUsers().list_next(req, resp)
    return by_device


def list_mac_devices(creds: service_account.Credentials, view: str):
    svc = build("cloudidentity", "v1", credentials=creds, cache_discovery=False)
    emails_by_device = fetch_mac_user_emails(svc)
    req = svc.devices().list(
        customer="customers/my_customer",
        filter="type:mac",
        view=view,
    )
    while req is not None:
        resp = req.execute()
        for d in resp.get("devices", []):
            d["userEmails"] = emails_by_device.get(_device_id(d.get("name", "")), [])
            yield d
        req = svc.devices().list_next(req, resp)


def infer_source(d: dict) -> str:
    # The Cloud Identity API doesn't expose a "reporting agent" field; each
    # client (Drive desktop, EV browser extension, EV + native helper) creates
    # its own Device record with the subset of signals it can collect. We
    # classify by which signals are present.
    has_sn = bool(d.get("serialNumber"))
    has_enc = bool(d.get("encryptionState"))
    has_host = bool(d.get("hostname"))
    has_mfr = bool(d.get("manufacturer"))
    if has_sn and has_enc:
        return "EV + native helper"
    if has_sn and has_host and not has_enc:
        return "Drive for Desktop"
    if has_enc and has_mfr and not has_sn:
        return "EV (browser only)"
    if d.get("model") == "Mac OS":
        return "stale / minimal"
    return "unknown"


def render_table(devices: list[dict]) -> str:
    rows = [
        (
            ", ".join(d.get("userEmails") or []) or "-",
            infer_source(d),
            d.get("serialNumber", "-"),
            d.get("model", "-"),
            d.get("assetTag", "-"),
            d.get("encryptionState", "-"),
            d.get("lastSyncTime", "-"),
        )
        for d in devices
    ]
    headers = ("USER", "SOURCE (inferred)", "SERIAL", "MODEL", "ASSET_TAG", "ENCRYPTION", "LAST_SYNC")
    widths = [
        max(len(str(r[i])) for r in (rows + [headers]))
        for i in range(len(headers))
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines.extend(fmt.format(*r) for r in rows)
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true", help="Dump raw JSON instead of a table.")
    p.add_argument(
        "--view",
        choices=["USER_ASSIGNED_DEVICES", "COMPANY_INVENTORY"],
        default="USER_ASSIGNED_DEVICES",
        help="Which device set to list (default: USER_ASSIGNED_DEVICES, where "
             "Endpoint Verification Macs live).",
    )
    args = p.parse_args()

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<a super-admin in your tenant>", file=sys.stderr)
        return 2

    creds = build_credentials(sa_email, admin_email)
    devices = list(list_mac_devices(creds, args.view))

    if args.json:
        json.dump(devices, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_table(devices))
        print(f"\n{len(devices)} Mac device(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
