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
from concurrent.futures import ThreadPoolExecutor

import google.auth
from google.auth import iam
from google.auth.transport.requests import AuthorizedSession, Request
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


def fetch_mac_device_users(svc) -> dict[str, list[dict]]:
    """deviceId -> [{'name', 'userEmail'}, ...] for every Mac DeviceUser, in one pass."""
    by_device: dict[str, list[dict]] = {}
    req = svc.devices().deviceUsers().list(
        parent="devices/-",
        customer="customers/my_customer",
        filter="type:mac",
    )
    while req is not None:
        resp = req.execute()
        for du in resp.get("deviceUsers", []):
            by_device.setdefault(_device_id(du.get("name", "")), []).append({
                "name": du.get("name", ""),
                "userEmail": du.get("userEmail", ""),
            })
        req = svc.devices().deviceUsers().list_next(req, resp)
    return by_device


def fetch_client_ids(session: AuthorizedSession, device_user_name: str) -> list[str]:
    """List clientState entries under a DeviceUser and return their trailing IDs.

    A ClientState resource is named
        devices/{device}/deviceUsers/{deviceUser}/clientStates/{partner}
    where {partner} identifies a Context-Aware Access partner that has
    registered signals (Crowdstrike, Jamf, custom partner integrations, ...).

    Confirmed empirically (2026-05-29): first-party Google clients including
    Endpoint Verification do NOT write entries here; this surface is for
    3rd-party CAA partners only. For a tenant with no partner integrations
    this list will always be empty, and that's expected.

    Uses a raw AuthorizedSession (not the discovery client) so callers can
    parallelize across DeviceUsers safely — httplib2 is not thread-safe.
    """
    ids: list[str] = []
    url = f"https://cloudidentity.googleapis.com/v1/{device_user_name}/clientStates"
    params: dict = {"customer": "customers/my_customer"}
    while True:
        r = session.get(url, params=params)
        r.raise_for_status()
        data = r.json()
        for cs in data.get("clientStates", []):
            name = cs.get("name", "")
            tail = name.rsplit("/", 1)[-1] if name else ""
            if tail:
                ids.append(tail)
        token = data.get("nextPageToken")
        if not token:
            return ids
        params["pageToken"] = token


def list_mac_devices(creds: service_account.Credentials, view: str, with_clients: bool):
    svc = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )
    users_by_device = fetch_mac_device_users(svc)

    # Pre-compute clientIds in parallel before yielding rows, since downstream
    # rendering needs them aligned with the device sequence. Cheaper to fan
    # out once than to interleave per-device.
    client_ids_by_du: dict[str, list[str]] = {}
    if with_clients:
        all_du_names = [u["name"] for du_list in users_by_device.values() for u in du_list]
        session = AuthorizedSession(creds)
        with ThreadPoolExecutor(max_workers=10) as pool:
            for du_name, ids in zip(
                all_du_names,
                pool.map(lambda n: fetch_client_ids(session, n), all_du_names),
            ):
                client_ids_by_du[du_name] = ids

    req = svc.devices().list(
        customer="customers/my_customer",
        filter="type:mac",
        view=view,
    )
    while req is not None:
        resp = req.execute()
        for d in resp.get("devices", []):
            users = users_by_device.get(_device_id(d.get("name", "")), [])
            d["userEmails"] = [u["userEmail"] for u in users if u.get("userEmail")]
            if with_clients:
                seen: list[str] = []
                for u in users:
                    for cid in client_ids_by_du.get(u["name"], []):
                        if cid not in seen:
                            seen.append(cid)
                d["clientIds"] = seen
            yield d
        req = svc.devices().list_next(req, resp)


def classify_signals(d: dict) -> str:
    # The Cloud Identity API doesn't expose a "reporting agent" field. Signals
    # arrive from whichever first-party Google client is signed in with a
    # managed identity — a Chrome session with any first-party extension
    # (Docs Offline, Endpoint Verification, Drive web, ...) supplies browser-
    # level signals, while native apps (Drive for Desktop, EV's native helper
    # .pkg, ...) supply hardware identifiers. We can't tell which from the
    # response, so we describe the *signal mix* present, not the source.
    has_sn = bool(d.get("serialNumber"))
    has_enc = bool(d.get("encryptionState"))
    has_host = bool(d.get("hostname"))
    if has_sn and has_enc:
        return "browser + hardware"
    if has_sn and has_host and not has_enc:
        return "hardware only"
    if has_enc and not has_sn:
        return "browser only"
    if d.get("model") == "Mac OS":
        return "stale / minimal"
    return "unknown"


def render_table(devices: list[dict], with_clients: bool) -> str:
    def row(d: dict) -> tuple:
        base = (
            ", ".join(d.get("userEmails") or []) or "-",
            classify_signals(d),
            d.get("serialNumber", "-"),
            d.get("model", "-"),
            d.get("assetTag", "-"),
            d.get("encryptionState", "-"),
            d.get("lastSyncTime", "-"),
        )
        if with_clients:
            return base + (", ".join(d.get("clientIds") or []) or "-",)
        return base

    rows = [row(d) for d in devices]
    headers = ("USER", "SIGNALS", "SERIAL", "MODEL", "ASSET_TAG", "ENCRYPTION", "LAST_SYNC")
    if with_clients:
        headers = headers + ("CLIENTS",)
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
    p.add_argument(
        "--clients",
        action="store_true",
        help="Also list 3rd-party Context-Aware Access partner ClientStates per "
             "device-user. Empty unless the tenant has a CAA partner (Crowdstrike, "
             "Jamf, etc.) writing signals; first-party Google clients including "
             "Endpoint Verification do not appear here.",
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
    devices = list(list_mac_devices(creds, args.view, args.clients))

    if args.json:
        json.dump(devices, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_table(devices, args.clients))
        print(f"\n{len(devices)} Mac device(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
