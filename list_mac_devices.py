#!/usr/bin/env python3
"""List all MAC_OS devices in the Workspace tenant with their encryption status.

Auth: keyless. Uses your local gcloud ADC + the IAM signJwt API to mint a
domain-wide-delegated access token impersonating WORKSPACE_ADMIN_EMAIL.
"""
from __future__ import annotations

import time
_T_MODULE_START = time.perf_counter()

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import google.auth
from google.auth import iam
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices.readonly"]

# Per-batch size for BatchHttpRequest. Google recommends <=50; hard cap is 1000.
_BATCH_SIZE = 50


def build_credentials(
    sa_email: str, admin_email: str, scopes: list[str]
) -> service_account.Credentials:
    source_creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/iam"],
    )
    signer = iam.Signer(Request(), source_creds, sa_email)
    return service_account.Credentials(
        signer=signer,
        service_account_email=sa_email,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=scopes,
        subject=admin_email,
    )


def _device_id(resource_name: str) -> str:
    # resource_name is "devices/{deviceId}" or "devices/{deviceId}/deviceUsers/{...}"
    parts = resource_name.split("/")
    return parts[1] if len(parts) >= 2 and parts[0] == "devices" else ""


def fetch_device_users_per_device(
    svc, device_names: list[str]
) -> dict[str, list[dict]]:
    """deviceId -> [{'name', 'userEmail'}, ...] via per-device deviceUsers.list, batched.

    Replaces the bulk `parent="devices/-"` paginated call. For tenants with
    accumulated session history the bulk call's server-side cost (filtering
    and paginating thousands of records) dominates; per-device calls operate
    on a smaller working set each, and 50 fit in a single batch envelope.

    Does not handle nextPageToken — in practice a single device's session
    history fits comfortably in the default page. If we ever see this in the
    wild we'll fall back to a paginated tail for those devices.
    """
    if not device_names:
        return {}
    requests = {
        f"u{i}": svc.devices().deviceUsers().list(
            parent=name,
            customer="customers/my_customer",
            fields="deviceUsers(name,userEmail),nextPageToken",
        )
        for i, name in enumerate(device_names)
    }
    responses = _run_batch(svc, requests)
    by_device: dict[str, list[dict]] = {}
    for rid, resp in responses.items():
        device_name = device_names[int(rid[1:])]
        device_id = _device_id(device_name)
        by_device[device_id] = [
            {"name": du.get("name", ""), "userEmail": du.get("userEmail", "")}
            for du in (resp.get("deviceUsers") or [])
        ]
    return by_device


def _run_batch(svc, requests_by_id: dict[str, object]) -> dict[str, dict]:
    """Execute a {request_id: HttpRequest} map via BatchHttpRequest in chunks.

    Returns {request_id: response_dict}. Raises on the first sub-request
    error — matches the prior ThreadPoolExecutor behavior where any raise
    in a worker propagated through `pool.map`.
    """
    results: dict[str, dict] = {}
    errors: list[tuple[str, Exception]] = []

    def cb(request_id, response, exception):
        if exception is not None:
            errors.append((request_id, exception))
        else:
            results[request_id] = response

    items = list(requests_by_id.items())
    for start in range(0, len(items), _BATCH_SIZE):
        batch = svc.new_batch_http_request(callback=cb)
        for rid, req in items[start:start + _BATCH_SIZE]:
            batch.add(req, request_id=rid)
        batch.execute()

    if errors:
        rid, exc = errors[0]
        raise RuntimeError(f"batch sub-request {rid} failed: {exc}") from exc
    return results


def extract_browser(full_device: dict) -> str:
    """Pull a short 'Chrome <version>' string from the EV signal block, if present.

    Only Chrome appears here — EV is a Chrome extension, so other browsers
    (Firefox, Safari, Edge) never report signals through this surface. Returns
    empty string when EV isn't reporting for this device.
    """
    ev = full_device.get("endpointVerificationSpecificAttributes") or {}
    for ba in ev.get("browserAttributes", []):
        chrome = ba.get("chromeBrowserInfo") or {}
        version = chrome.get("browserVersion")
        if version:
            return f"Chrome {version}"
    return ""


def list_mac_devices(
    creds: service_account.Credentials,
    view: str,
    with_clients: bool,
    timing: dict | None = None,
):
    def record(label: str, t_start: float) -> None:
        if timing is not None:
            timing[label] = time.perf_counter() - t_start

    # Two service instances so the two batched fan-outs below can run on
    # separate threads — httplib2 (under the discovery client) is not
    # thread-safe per-instance, so we don't want both threads sharing one svc.
    # static_discovery=True keeps each build() ~4ms (no network).
    t = time.perf_counter()
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
    record("discovery build (x2)", t)

    # Step 1: devices.list — we need device names before we can fan out the
    # per-device deviceUsers.list and devices.get calls. fields mask trims the
    # payload to just `name` since we re-fetch the full record via devices.get.
    t = time.perf_counter()
    summaries: list[dict] = []
    req = svc.devices().list(
        customer="customers/my_customer",
        filter="type:mac",
        view=view,
        fields="devices(name),nextPageToken",
    )
    while req is not None:
        resp = req.execute()
        summaries.extend(resp.get("devices", []))
        req = svc.devices().list_next(req, resp)
    record("devices.list", t)

    device_names = [d["name"] for d in summaries]

    # Step 2: parallel fan-out — per-device deviceUsers.list batched + per-device
    # devices.get batched. Both depend on device names from step 1; neither
    # depends on the other. Each batch goes through its own service instance.
    def _fetch_users() -> tuple[dict[str, list[dict]], float]:
        t0 = time.perf_counter()
        out = fetch_device_users_per_device(svc, device_names)
        return out, time.perf_counter() - t0

    def _fetch_full_devices() -> tuple[dict[str, dict], float]:
        t0 = time.perf_counter()
        get_requests = {
            f"d{i}": svc2.devices().get(name=name)
            for i, name in enumerate(device_names)
        }
        get_responses = _run_batch(svc2, get_requests)
        out = {
            device_names[int(rid[1:])]: resp
            for rid, resp in get_responses.items()
        }
        return out, time.perf_counter() - t0

    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_users = pool.submit(_fetch_users)
        f_full = pool.submit(_fetch_full_devices)
        users_by_device, users_elapsed = f_users.result()
        full_by_name, full_elapsed = f_full.result()
    parallel_wall = time.perf_counter() - t
    if timing is not None:
        timing["[parallel] deviceUsers.list batched"] = users_elapsed
        timing[f"[parallel] devices.get batched (n={len(device_names)})"] = full_elapsed
        timing["[parallel] section wall"] = parallel_wall

    client_ids_by_du: dict[str, list[str]] = {}
    if with_clients:
        t = time.perf_counter()
        # ClientState resources are named
        #   devices/{device}/deviceUsers/{deviceUser}/clientStates/{partner}
        # where {partner} is a Context-Aware Access partner (Crowdstrike, Jamf,
        # …). Confirmed empirically: first-party Google clients including
        # Endpoint Verification do NOT write entries here, so on a tenant with
        # no CAA partner integrations every list will return empty.
        #
        # We don't paginate — in practice each DeviceUser has at most a handful
        # of ClientStates (one per partner), well under the default page size.
        all_du_names = [u["name"] for du_list in users_by_device.values() for u in du_list]
        cs_requests = {
            f"c{i}": svc.devices().deviceUsers().clientStates().list(
                parent=du_name,
                customer="customers/my_customer",
            )
            for i, du_name in enumerate(all_du_names)
        }
        cs_responses = _run_batch(svc, cs_requests)
        for rid, resp in cs_responses.items():
            du_name = all_du_names[int(rid[1:])]
            ids: list[str] = []
            for cs in resp.get("clientStates", []) or []:
                name = cs.get("name", "")
                tail = name.rsplit("/", 1)[-1] if name else ""
                if tail:
                    ids.append(tail)
            client_ids_by_du[du_name] = ids
        record(f"clientStates.list batched (n={len(all_du_names)})", t)

    for d in summaries:
        full = full_by_name.get(d["name"], {})
        # Merge fields the summary view omitted (e.g. hostname, EV attributes).
        for k, v in full.items():
            d.setdefault(k, v)
        users = users_by_device.get(_device_id(d.get("name", "")), [])
        # Dedupe: Google creates a new DeviceUser record per sign-in session,
        # so a frequently-used device yields many records with the same email.
        d["userEmails"] = list(dict.fromkeys(
            u["userEmail"] for u in users if u.get("userEmail")
        ))
        d["browser"] = extract_browser(full)
        if with_clients:
            seen: list[str] = []
            for u in users:
                for cid in client_ids_by_du.get(u["name"], []):
                    if cid not in seen:
                        seen.append(cid)
            d["clientIds"] = seen
        yield d


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
            d.get("browser") or "-",
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
    headers = ("USER", "BROWSER", "SIGNALS", "SERIAL", "MODEL", "ASSET_TAG", "ENCRYPTION", "LAST_SYNC")
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
    p.add_argument(
        "--exclude-stale", action="store_true",
        help="Drop devices the classifier labels 'stale / minimal' (no serial, "
             "no encryption state — typically dormant records with no recent signal).",
    )
    p.add_argument(
        "--require-serial", action="store_true",
        help="Drop devices with no serialNumber (a stricter cut than "
             "--exclude-stale; also drops 'browser only' records).",
    )
    p.add_argument(
        "--timing", action="store_true",
        help="Print a per-phase wall-clock breakdown to stderr after the run.",
    )
    args = p.parse_args()

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Mobile Device Management read privilege>", file=sys.stderr)
        return 2

    timing: dict[str, float] | None = {} if args.timing else None
    t_main_start = time.perf_counter()
    if timing is not None:
        timing["module import (post 'import time')"] = t_main_start - _T_MODULE_START

    t = time.perf_counter()
    creds = build_credentials(sa_email, admin_email, SCOPES)
    if timing is not None:
        timing["build_credentials (local)"] = time.perf_counter() - t

    # Force the signJwt + token-exchange RTTs to happen NOW so they show up as
    # their own phase, rather than getting folded into the first API call.
    t = time.perf_counter()
    creds.refresh(Request())
    if timing is not None:
        timing["auth refresh (signJwt + token)"] = time.perf_counter() - t

    devices = list(list_mac_devices(creds, args.view, args.clients, timing=timing))
    if args.exclude_stale:
        devices = [d for d in devices if classify_signals(d) != "stale / minimal"]
    if args.require_serial:
        devices = [d for d in devices if d.get("serialNumber")]

    t = time.perf_counter()
    if args.json:
        json.dump(devices, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_table(devices, args.clients))
        print(f"\n{len(devices)} Mac device(s).")
    if timing is not None:
        timing["render + print"] = time.perf_counter() - t
        wall = time.perf_counter() - _T_MODULE_START
        width = max(len(k) for k in timing)
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
        # The two individual [parallel] entries overlap each other and are
        # subsumed by [parallel] section wall — don't double-count them in the
        # phases total.
        phases_total = sum(
            v for k, v in timing.items()
            if not (k.startswith("[parallel]") and k != "[parallel] section wall")
        )
        print(f"  {'-' * width}  --------", file=sys.stderr)
        print(f"  {'phases total (no parallel overlap)':<{width}}  {phases_total*1000:8.1f} ms", file=sys.stderr)
        print(f"  {'wall (post import time)':<{width}}  {wall*1000:8.1f} ms", file=sys.stderr)
        print(f"  (interpreter+import-time startup not included in either)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
