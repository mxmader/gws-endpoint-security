#!/usr/bin/env python3
"""List active Mac devices in the Workspace tenant with their encryption status.

By default surfaces only devices that (a) report a serial number and (b) have
synced in the last 30 days, deduped by serial. Rows are sorted so Macs
with undetermined encryption surface first, then NOT_ENCRYPTED, then
ENCRYPTED — at-risk records are eye-scannable. The
Cloud Identity Devices API holds many records per physical Mac (per user /
app / OS version / login vector); without filtering, a noisy tenant easily
exceeds the `devices_read_requests` quota (1500/min). Use `--last-sync-days
N` to widen the window; use `--include-browser` to pull each survivor's
Chrome version from the EV signal block — at the cost of one extra
`devices.get` call per surviving device. Use `--format json|csv` and
`--output PATH` for non-interactive consumption.

Auth: keyless. Uses your local gcloud ADC + the IAM signJwt API to mint a
domain-wide-delegated access token impersonating WORKSPACE_ADMIN_EMAIL.
"""
from __future__ import annotations

import time
_T_MODULE_START = time.perf_counter()

import argparse
import csv
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence

import google.auth
import pycountry
from google.auth import iam
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/cloud-identity.devices.readonly"]

# Per-batch size for BatchHttpRequest. Google recommends <=50; hard cap is 1000.
_BATCH_SIZE = 50

# Decoder ring for Apple model identifiers (e.g. "Mac16,6" → "MacBook Pro 14\" M4 Max
# (2024)"). Maintained by hand at the repo root; expand as new models appear in
# the field. Falls back gracefully to the raw identifier when a model is absent
# from the file or the file itself is missing/malformed. To be retired when we
# can call the Apple Business Manager API.
_MAC_MODELS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac_models.json")


def _load_mac_models() -> dict[str, str]:
    try:
        with open(_MAC_MODELS_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


_MAC_MODELS = _load_mac_models()
# Comma-insensitive index. Some signal sources (e.g. the CAA event log feeding
# list_caa_events.py) report the identifier with the comma stripped — "Mac1610"
# instead of "Mac16,10" — so an exact lookup misses. Stripping commas is
# collision-free across the current catalog, so we fall back to this index.
_MAC_MODELS_NOCOMMA = {k.replace(",", ""): v for k, v in _MAC_MODELS.items()}


def decode_model(raw: str | None) -> str:
    """Map an Apple model identifier to a human-readable name, or '' if unknown.

    Tolerant of the comma-stripped form ("Mac1610") some sources emit.
    """
    if not raw:
        return ""
    hit = _MAC_MODELS.get(raw)
    if hit is not None:
        return hit
    return _MAC_MODELS_NOCOMMA.get(raw.replace(",", ""), "")


def model_cell(d: dict) -> str:
    """MODEL-column text: the decoded name, or the raw identifier flagged with
    a trailing "*" when it isn't in mac_models.json (a hint to add it). The
    "Mac OS" stale-registration placeholder is left unflagged — it's a known
    non-identifier, not a catalog gap."""
    decoded = d.get("modelName")
    if decoded:
        return decoded
    raw = d.get("model")
    if not raw:
        return "-"
    return raw if raw == "Mac OS" else f"{raw}*"


def device_id_cell(d: dict) -> str:
    """DEVICE_ID-column text: the Cloud Identity deviceId(s) for this row.

    A physical device can hold several Cloud Identity records (one per reporting
    agent), so this joins every known id — letting a CAA_DEVICE_ID from
    list_caa_events.py be matched back to a device here. Falls back to the id
    parsed from the resource `name`; "-" when none.
    """
    ids = d.get("deviceIds")
    if not ids:
        one = _device_id(d.get("name", "") or "")
        ids = [one] if one else []
    return ", ".join(ids) or "-"


# --- Location / network rendering (shared by list_signins.py + list_caa_events.py) ---
# Both scripts read the `networkInfo` block Google stamps on Reports API
# activity records (login + context_aware_access). These helpers decode it.

def _country_name(alpha_2: str) -> str:
    """ISO 3166-1 alpha-2 country code -> readable name ('' if unknown).
    Prefers the short common name (e.g. 'South Korea' over 'Korea, Republic of').
    """
    c = pycountry.countries.get(alpha_2=alpha_2)
    if not c:
        return ""
    return getattr(c, "common_name", None) or c.name


def render_location(network_info: dict) -> str:
    """Format `networkInfo` into a human-friendly "Subdivision, Country" string.

    Decodes the ISO 3166 codes Google supplies — `subdivisionCode` (e.g.
    "FR-IDF", "US-UT") and `regionCode` (the country, e.g. "FR") — via
    pycountry's bundled ISO database. No external geo-IP lookup. Falls back to
    the raw code if it isn't in the ISO database.
    """
    info = network_info or {}
    sub = info.get("subdivisionCode") or ""
    region = info.get("regionCode") or ""
    if sub:
        match = pycountry.subdivisions.get(code=sub)
        country = _country_name(sub.split("-")[0])
        if match and country:
            return f"{match.name}, {country}"
        if match:
            return match.name
        # Unknown subdivision: raw code, decorated with the country if known.
        return f"{sub} ({country})" if country else sub
    if region:
        return _country_name(region) or region
    return ""


def render_ip_asn(network_info: dict) -> str:
    """Render the native "IP ASN" (ASN + subdivision/region) from `networkInfo`,
    surfaced as Google supplies it — distinct from the decoded `render_location`.

    Defensive about subfield names: Google's docs don't pin the ASN field down,
    so we try the likely keys and fall back to '' when none are present. The
    exact shape is tenant-confirmed from a raw activity dump.
    """
    info = network_info or {}
    asn = (
        info.get("asn")
        or info.get("autonomousSystemNumber")
        or info.get("asNumber")
        or info.get("regionCodeAsn")
        or ""
    )
    asn = str(asn).strip()
    label = ""
    if asn:
        label = asn if asn.upper().startswith("AS") else f"AS{asn}"
    geo = info.get("subdivisionCode") or info.get("regionCode") or ""
    if geo:
        label = f"{label} ({geo})" if label else geo
    return label


# Bounded retry for transient errors (429 RATE_LIMIT_EXCEEDED, 5xx).
_MAX_RETRIES = 4
_BACKOFF_BASE_SEC = 2.0


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


def _http_status(exc: BaseException) -> int | None:
    if isinstance(exc, HttpError) and getattr(exc, "resp", None) is not None:
        try:
            return int(exc.resp.status)
        except (AttributeError, ValueError, TypeError):
            return None
    return None


def _is_retryable(exc: BaseException) -> bool:
    status = _http_status(exc)
    return status == 429 or (status is not None and 500 <= status < 600)


def _retry_after_seconds(exc: BaseException) -> float | None:
    """Parse a Retry-After response header from an HttpError, if present."""
    if not isinstance(exc, HttpError) or getattr(exc, "resp", None) is None:
        return None
    try:
        ra = exc.resp.get("retry-after")
    except AttributeError:
        return None
    if not ra:
        return None
    try:
        return float(ra)
    except (TypeError, ValueError):
        return None


def _backoff_seconds(attempt: int, exc: BaseException | None = None) -> float:
    if exc is not None:
        ra = _retry_after_seconds(exc)
        if ra is not None:
            return ra
    delay = _BACKOFF_BASE_SEC * (2 ** attempt)
    return delay * (1 + random.uniform(-0.25, 0.25))


def _execute(req):
    """Execute a single HttpRequest with retry on 429/5xx transient errors."""
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return req.execute()
        except Exception as exc:
            if attempt == _MAX_RETRIES or not _is_retryable(exc):
                raise
            delay = _backoff_seconds(attempt, exc)
            print(
                f"  retry {attempt + 1}/{_MAX_RETRIES} after {delay:.1f}s "
                f"(HTTP {_http_status(exc)}): {exc}",
                file=sys.stderr,
            )
            time.sleep(delay)


def _run_batch(
    svc,
    request_factories: dict[str, Callable[[], object]],
    ignore_statuses: frozenset[int] | set[int] = frozenset(),
) -> dict[str, dict]:
    """Execute {request_id: factory()} via BatchHttpRequest with per-sub-request retry.

    Factories (not pre-built HttpRequest objects) so each retry can mint a fresh
    request — googleapiclient's HttpRequest is not guaranteed re-executable
    after an error. Retries only the failing sub-requests, not the whole batch.

    `ignore_statuses` — HTTP statuses (e.g. {404}) treated as success rather
    than fatal. The sub-request's result becomes `{}`. Useful for idempotent
    deletes where "already gone" is the desired state.
    """
    results: dict[str, dict] = {}
    pending: dict[str, Callable[[], object]] = dict(request_factories)

    for attempt in range(_MAX_RETRIES + 1):
        if not pending:
            return results

        retry_pending: dict[str, Callable[[], object]] = {}
        retry_excs: list[BaseException] = []
        fatal: tuple[str, BaseException] | None = None

        def cb(request_id, response, exception):
            nonlocal fatal
            if exception is None:
                results[request_id] = response
            elif _http_status(exception) in ignore_statuses:
                results[request_id] = {}
            elif _is_retryable(exception):
                retry_pending[request_id] = pending[request_id]
                retry_excs.append(exception)
            elif fatal is None:
                fatal = (request_id, exception)

        items = list(pending.items())
        for start in range(0, len(items), _BATCH_SIZE):
            batch = svc.new_batch_http_request(callback=cb)
            for rid, factory in items[start:start + _BATCH_SIZE]:
                batch.add(factory(), request_id=rid)
            batch.execute()

        if fatal is not None:
            rid, exc = fatal
            raise RuntimeError(f"batch sub-request {rid} failed: {exc}") from exc

        if not retry_pending:
            return results

        if attempt == _MAX_RETRIES:
            rid = next(iter(retry_pending))
            raise RuntimeError(
                f"batch sub-request {rid} still failing after "
                f"{_MAX_RETRIES} retries (last HTTP {_http_status(retry_excs[-1])})"
            )

        # Honor the longest Retry-After across failing sub-requests, else
        # exponential backoff.
        delay = max(_backoff_seconds(attempt, exc) for exc in retry_excs)
        print(
            f"  batch retry {attempt + 1}/{_MAX_RETRIES}: "
            f"{len(retry_pending)} sub-request(s), sleeping {delay:.1f}s",
            file=sys.stderr,
        )
        time.sleep(delay)
        pending = retry_pending

    return results


def fetch_device_users_for_user(
    svc, user_email: str, type_filter: str | None = None,
) -> tuple[dict[str, list[dict]], bool]:
    """Return ({device_id: [DeviceUser, ...]}, server_side_filtered) for one user.

    `devices.deviceUsers.list` defers its `filter` semantics to the Admin SDK
    "Mobile device search fields" (per
    https://docs.cloud.google.com/identity/docs/reference/rest/v1/devices.deviceUsers/list).
    On that surface, multiple operators are **space-separated**, not joined
    with `AND` — we initially used `type:mac AND email:<X>` and the API
    silently returned zero rows. The correct form is `type:mac email:<X>`.

    `type_filter` optionally scopes the server-side query with a `type:<token>`
    (e.g. `mac`); None filters on `email:<X>` alone, returning the user's
    devices of every type for the caller to bucket client-side.

    Server-side success is verified by also requiring a case-insensitive
    client-side match before keeping a row; if the API still returns nothing
    (e.g., for a tenant where the filter semantics regress), we fall back to
    the bulk listing + client-side filter so the script never silently
    under-counts.
    """
    target = user_email.lower()
    by_device: dict[str, list[dict]] = {}
    filt = (
        f"type:{type_filter} email:{user_email}"
        if type_filter else f"email:{user_email}"
    )

    try:
        req = svc.devices().deviceUsers().list(
            parent="devices/-",
            customer="customers/my_customer",
            filter=filt,
            fields="deviceUsers(name,userEmail),nextPageToken",
        )
        while req is not None:
            resp = _execute(req)
            for du in resp.get("deviceUsers") or []:
                if (du.get("userEmail") or "").lower() != target:
                    continue
                device_id = _device_id(du.get("name", ""))
                if not device_id:
                    continue
                by_device.setdefault(device_id, []).append({
                    "name": du.get("name", ""),
                    "userEmail": du.get("userEmail", ""),
                })
            req = svc.devices().deviceUsers().list_next(req, resp)
        if by_device:
            return by_device, True
        # Server returned zero — verify by bulk before reporting "no devices".
    except HttpError as exc:
        if _http_status(exc) != 400:
            raise
        # Filter rejected — fall through to bulk.

    # Fallback: bulk listing + client-side filter (also our verification path
    # when the server filter returned zero rows).
    by_device = {}
    for dev_id, dus in fetch_device_users(svc, type_filter).items():
        filtered = [u for u in dus if (u.get("userEmail") or "").lower() == target]
        if filtered:
            by_device[dev_id] = filtered
    return by_device, False


def fetch_user_device_users(
    svc, user_email: str,
) -> tuple[dict[str, list[dict]], bool]:
    """Mac-scoped user lookup. Wrapper over `fetch_device_users_for_user(.., 'mac')`."""
    return fetch_device_users_for_user(svc, user_email, "mac")


def fetch_device_users(
    svc, type_filter: str | None = None,
) -> dict[str, list[dict]]:
    """deviceId -> [{'name', 'userEmail'}, ...] for every DeviceUser, bulk paginated.

    Single `parent="devices/-"` paginated call across the whole tenant. Slower
    per-call than per-device fan-out but uses far fewer quota units, which is
    the binding constraint on noisy tenants. Caller intersects the result with
    the post-filter survivor set to drop attribution for pruned devices.

    `type_filter` — an Admin SDK "Mobile device search fields" `type:` token
    (e.g. `mac`, `android`, `ios`) to scope the listing server-side, or None to
    list device-users of every type. Note these tokens are space-separated, not
    `AND`-joined — see `fetch_user_device_users` for the gory detail.
    """
    by_device: dict[str, list[dict]] = {}
    kwargs = dict(
        parent="devices/-",
        customer="customers/my_customer",
        fields="deviceUsers(name,userEmail),nextPageToken",
    )
    if type_filter:
        kwargs["filter"] = f"type:{type_filter}"
    req = svc.devices().deviceUsers().list(**kwargs)
    while req is not None:
        resp = _execute(req)
        for du in resp.get("deviceUsers", []) or []:
            device_id = _device_id(du.get("name", ""))
            if not device_id:
                continue
            by_device.setdefault(device_id, []).append({
                "name": du.get("name", ""),
                "userEmail": du.get("userEmail", ""),
            })
        req = svc.devices().deviceUsers().list_next(req, resp)
    return by_device


def fetch_mac_device_users(svc) -> dict[str, list[dict]]:
    """Bulk Mac DeviceUsers. Thin wrapper over `fetch_device_users(svc, 'mac')`."""
    return fetch_device_users(svc, "mac")


# Field mask broad enough for the non-Mac listers (mobile + everything-else),
# which surface posture signals the Mac report doesn't (compromisedState,
# securityPatchTime, the Android attribute block, ...). `collect_devices` uses
# it; the Mac path keeps its own narrower mask above.
DEVICE_LIST_FIELDS = (
    "devices(name,deviceType,serialNumber,lastSyncTime,model,osVersion,"
    "manufacturer,brand,compromisedState,encryptionState,securityPatchTime,"
    "managementState,ownerType,releaseVersion,buildNumber,hostname,imei,meid,"
    "networkOperator,enabledDeveloperOptions,enabledUsbDebugging,"
    "androidSpecificAttributes),nextPageToken"
)


def collect_devices(
    creds: service_account.Credentials,
    *,
    device_filter: Callable[[dict], bool],
    view: str = "USER_ASSIGNED_DEVICES",
    last_sync_days: int = 30,
    fields: str = DEVICE_LIST_FIELDS,
    require_serial: bool = False,
    user_type_filters: Sequence[str] | None = None,
    user_email: str | None = None,
) -> list[dict]:
    """Generic active-device collector shared by the non-Mac listers.

    Tenant-wide path: lists the whole tenant once (no server-side `type:`
    filter — the friendly token spellings beyond `mac`/`android`/`ios` are
    undocumented, so we bucket client-side via `device_filter` for robustness),
    drops records that haven't synced within `last_sync_days`, dedups to one row
    per physical device, and attaches user attribution.

    Focused path (`user_email` set): skips the tenant-wide `devices.list`
    entirely. Runs one server-side `email:<X>` filter on `deviceUsers.list`
    (falling back to bulk + client filter if the tenant regresses), then a
    batched `devices.get` on just that user's device set. `device_filter` still
    buckets the result by `deviceType` client-side — there is no server token
    for "not mac/android/ios" — so a `--user` lookup returns only the device
    types this lister owns.

    `device_filter(d) -> bool` selects which `deviceType` records to keep.

    Dedup key is `serialNumber` when present, else the device's own id; the most
    recently synced record wins, and `userEmails` is the union across every
    record sharing the key (multi-user devices). When `require_serial` is set,
    serial-less records are dropped entirely rather than kept under their id.

    `user_type_filters` scopes the bulk DeviceUsers fetch to those `type:`
    tokens (e.g. `["android", "ios"]`); None fetches every type. Ignored on the
    focused path. Either way attribution is intersected against the survivor
    set, so over-fetching only costs bandwidth, never correctness.

    Each survivor dict is returned with two added keys: `userEmails` (list) and
    `deviceIds` (the merged set of source records' ids).
    """
    svc = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )

    if user_email:
        # Focused path: email filter server-side, then devices.get the result.
        users_by_device, _ = fetch_device_users_for_user(svc, user_email)
        device_names = [f"devices/{dev_id}" for dev_id in users_by_device]
        if device_names:
            get_factories: dict[str, Callable[[], object]] = {
                f"d{i}": (lambda nm=name: svc.devices().get(name=nm))
                for i, name in enumerate(device_names)
            }
            summaries = list(_run_batch(svc, get_factories).values())
        else:
            summaries = []
    else:
        # Tenant-wide path: list everything, then bulk DeviceUsers attribution.
        summaries = []
        req = svc.devices().list(
            customer="customers/my_customer", view=view, fields=fields,
        )
        while req is not None:
            resp = _execute(req)
            summaries.extend(resp.get("devices", []))
            req = svc.devices().list_next(req, resp)
        if user_type_filters:
            users_by_device = {}
            for tf in user_type_filters:
                for dev_id, dus in fetch_device_users(svc, tf).items():
                    users_by_device.setdefault(dev_id, []).extend(dus)
        else:
            users_by_device = fetch_device_users(svc)

    cutoff = datetime.now(timezone.utc) - timedelta(days=last_sync_days)
    key_to_device_ids: dict[str, set[str]] = {}
    survivors_by_key: dict[str, dict] = {}
    for d in summaries:
        if not device_filter(d):
            continue
        sync = _parse_sync(d)
        if sync is None or sync < cutoff:
            continue
        serial = (d.get("serialNumber") or "").strip()
        device_id = _device_id(d.get("name", ""))
        if require_serial and not serial:
            continue
        key = serial or device_id
        if not key:
            continue
        if device_id:
            key_to_device_ids.setdefault(key, set()).add(device_id)
        existing = survivors_by_key.get(key)
        existing_sync = _parse_sync(existing) if existing else None
        if existing_sync is None or existing_sync < sync:
            survivors_by_key[key] = d

    for key, d in survivors_by_key.items():
        emails: dict[str, None] = {}
        for dev_id in key_to_device_ids.get(key, set()):
            for u in users_by_device.get(dev_id, []):
                ue = u.get("userEmail")
                if ue:
                    emails[ue] = None
        d["userEmails"] = list(emails)
        d["deviceIds"] = sorted(key_to_device_ids.get(key, set()))

    return list(survivors_by_key.values())


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


def _parse_sync(d: dict) -> datetime | None:
    """RFC 3339 lastSyncTime -> timezone-aware datetime, or None if missing/invalid."""
    ts = d.get("lastSyncTime")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def list_mac_devices(
    creds: service_account.Credentials,
    view: str,
    with_clients: bool,
    last_sync_days: int,
    include_browser: bool,
    user_email: str | None = None,
    timing: dict | None = None,
):
    def record(label: str, t_start: float) -> None:
        if timing is not None:
            timing[label] = time.perf_counter() - t_start

    # Two service instances so the two batched/paginated calls below can run
    # on separate threads — httplib2 (under the discovery client) is not
    # thread-safe per-instance.
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

    # Two acquisition paths, both producing the same downstream shape:
    #   summaries        — list of device dicts with the filter+display fields
    #   users_by_device  — deviceId → [DeviceUser, ...] for user attribution
    #   full_by_name     — device name → full record (for EV browser attribute)
    if user_email:
        # Focused path: --user is set. Skip devices.list entirely. Try the
        # server-side `type:mac email:<X>` filter on deviceUsers.list — if it
        # returns rows, we paid for one targeted call. If it silently returns
        # zero (some tenants regress to broken semantics), we fall back to the
        # bulk listing + client-side filter so the script never under-counts.
        # Then devices.get on the resulting device IDs — which returns full
        # records including all the fields devices.list would have given us.
        t = time.perf_counter()
        users_by_device, server_filtered = fetch_user_device_users(svc, user_email)
        record(
            f"deviceUsers.list for user ({'server' if server_filtered else 'bulk'}-filter)",
            t,
        )
        device_names = [f"devices/{dev_id}" for dev_id in users_by_device]
        if device_names:
            t = time.perf_counter()
            get_factories: dict[str, Callable[[], object]] = {
                f"d{i}": (lambda nm=name: svc.devices().get(name=nm))
                for i, name in enumerate(device_names)
            }
            get_responses = _run_batch(svc, get_factories)
            full_by_name = {
                device_names[int(rid[1:])]: resp for rid, resp in get_responses.items()
            }
            summaries = list(full_by_name.values())
            record(f"devices.get batched (n={len(device_names)})", t)
        else:
            full_by_name = {}
            summaries = []
    else:
        # Tenant-wide path: devices.list with expanded projection, then
        # parallel bulk deviceUsers.list + batched devices.get (only when
        # --include-browser, since devices.list already supplies basic fields).
        t = time.perf_counter()
        list_fields = (
            "devices(name,serialNumber,lastSyncTime,model,osVersion,assetTag,"
            "encryptionState,hostname,deviceType),nextPageToken"
        )
        summaries = []
        req = svc.devices().list(
            customer="customers/my_customer",
            filter="type:mac",
            view=view,
            fields=list_fields,
        )
        while req is not None:
            resp = _execute(req)
            summaries.extend(resp.get("devices", []))
            req = svc.devices().list_next(req, resp)
        record(f"devices.list (raw_n={len(summaries)})", t)
        full_by_name = {}
        users_by_device = {}

    # Shared: client-side filter (active + serialed) + dedup by serial,
    # keeping the most recent record per serial (by lastSyncTime).
    t = time.perf_counter()
    cutoff = datetime.now(timezone.utc) - timedelta(days=last_sync_days)
    serial_to_device_ids: dict[str, set[str]] = {}
    survivors_by_serial: dict[str, dict] = {}
    for d in summaries:
        serial = (d.get("serialNumber") or "").strip()
        if not serial:
            continue
        sync = _parse_sync(d)
        if sync is None or sync < cutoff:
            continue
        device_id = _device_id(d.get("name", ""))
        if device_id:
            serial_to_device_ids.setdefault(serial, set()).add(device_id)
        existing = survivors_by_serial.get(serial)
        existing_sync = _parse_sync(existing) if existing else None
        if existing_sync is None or existing_sync < sync:
            survivors_by_serial[serial] = d
    record(f"filter+dedup (survivors_n={len(survivors_by_serial)})", t)

    survivor_names = [d["name"] for d in survivors_by_serial.values()]

    # Tenant-wide path only: parallel bulk deviceUsers.list + batched
    # devices.get on survivors. In the focused path we already have both.
    if not user_email:
        def _fetch_users_bulk() -> tuple[dict[str, list[dict]], float]:
            t0 = time.perf_counter()
            out = fetch_mac_device_users(svc)
            return out, time.perf_counter() - t0

        def _fetch_full_survivors() -> tuple[dict[str, dict], float]:
            t0 = time.perf_counter()
            if not include_browser or not survivor_names:
                return {}, time.perf_counter() - t0
            get_factories = {
                f"d{i}": (lambda nm=name: svc2.devices().get(name=nm))
                for i, name in enumerate(survivor_names)
            }
            get_responses = _run_batch(svc2, get_factories)
            return (
                {survivor_names[int(rid[1:])]: resp for rid, resp in get_responses.items()},
                time.perf_counter() - t0,
            )

        t = time.perf_counter()
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_users = pool.submit(_fetch_users_bulk)
            f_full = pool.submit(_fetch_full_survivors)
            users_by_device, users_elapsed = f_users.result()
            full_by_name, full_elapsed = f_full.result()
        parallel_wall = time.perf_counter() - t
        if timing is not None:
            timing["[parallel] deviceUsers.list bulk"] = users_elapsed
            full_label = f"n={len(survivor_names)}" if include_browser else "skipped"
            timing[f"[parallel] devices.get batched ({full_label})"] = full_elapsed
            timing["[parallel] section wall"] = parallel_wall

    # clientStates fan-out — survivors only, batched, with retry.
    client_ids_by_du: dict[str, list[str]] = {}
    if with_clients:
        t = time.perf_counter()
        survivor_du_names: list[str] = []
        for serial in survivors_by_serial:
            for dev_id in serial_to_device_ids.get(serial, set()):
                for u in users_by_device.get(dev_id, []):
                    if u.get("name"):
                        survivor_du_names.append(u["name"])
        if survivor_du_names:
            cs_factories: dict[str, Callable[[], object]] = {
                f"c{i}": (
                    lambda nm=du_name: svc.devices().deviceUsers().clientStates().list(
                        parent=nm, customer="customers/my_customer",
                    )
                )
                for i, du_name in enumerate(survivor_du_names)
            }
            cs_responses = _run_batch(svc, cs_factories)
            for rid, resp in cs_responses.items():
                du_name = survivor_du_names[int(rid[1:])]
                ids: list[str] = []
                for cs in resp.get("clientStates", []) or []:
                    tail = (cs.get("name", "") or "").rsplit("/", 1)[-1]
                    if tail:
                        ids.append(tail)
                client_ids_by_du[du_name] = ids
        record(f"clientStates.list batched (n={len(survivor_du_names)})", t)

    # Step 4: yield one row per surviving serial. userEmails is the union
    # across ALL device records that share this serial (multi-user Macs).
    for serial, d in survivors_by_serial.items():
        full = full_by_name.get(d["name"], {})
        for k, v in full.items():
            d.setdefault(k, v)

        emails: dict[str, None] = {}
        for dev_id in serial_to_device_ids.get(serial, set()):
            for u in users_by_device.get(dev_id, []):
                ue = u.get("userEmail")
                if ue:
                    emails[ue] = None
        d["userEmails"] = list(emails)

        # All Cloud Identity deviceIds for this physical Mac (one per reporting
        # agent). Lets a CAA_DEVICE_ID be matched back to a device here.
        d["deviceIds"] = sorted(serial_to_device_ids.get(serial, set()))

        # Enrich with a human-readable model name when we recognize the
        # identifier. JSON output keeps both `model` (raw) and `modelName`
        # (narrative, or "" when unknown).
        d["modelName"] = decode_model(d.get("model"))

        d["browser"] = extract_browser(full) if include_browser else ""

        if with_clients:
            seen: list[str] = []
            for dev_id in serial_to_device_ids.get(serial, set()):
                for u in users_by_device.get(dev_id, []):
                    for cid in client_ids_by_du.get(u.get("name", ""), []):
                        if cid not in seen:
                            seen.append(cid)
            d["clientIds"] = seen

        yield d


def classify_signals(d: dict) -> str:
    # The Cloud Identity API doesn't expose a "reporting agent" field. Signals
    # arrive from whichever first-party Google client is signed in with a
    # managed identity — a Chrome session with any first-party extension
    # (Docs Offline, Endpoint Verification, Drive web, ...) supplies Chrome-
    # level signals, while native apps (Drive for Desktop, EV's native helper
    # .pkg, ...) supply hardware identifiers. We label by Chrome rather than
    # "browser" because only Chrome carries the first-party extension surface
    # that pushes these signals — Firefox/Safari/Edge never appear here.
    has_sn = bool(d.get("serialNumber"))
    has_enc = bool(d.get("encryptionState"))
    has_host = bool(d.get("hostname"))
    if has_sn and has_enc:
        return "chrome + hardware"
    if has_sn and has_host and not has_enc:
        return "hardware only"
    if has_enc and not has_sn:
        return "chrome only"
    if d.get("model") == "Mac OS":
        return "stale / minimal"
    return "unknown"


def encryption_sort_key(d: dict) -> tuple:
    """Sort survivor Macs so the riskiest records surface first.

    Group 0: encryption status undetermined — missing, ENCRYPTION_STATE_
             UNSPECIFIED, UNSUPPORTED_BY_DEVICE, or any unrecognized value.
             Top priority for follow-up: we can't even confirm FileVault is
             on, so the device's posture is unknown.
    Group 1: NOT_ENCRYPTED — known gap.
    Group 2: ENCRYPTED — clean.
    Within each group: by primary userEmail then serialNumber.
    """
    enc = (d.get("encryptionState") or "").upper()
    if enc == "ENCRYPTED":
        group = 2
    elif enc == "NOT_ENCRYPTED":
        group = 1
    else:
        group = 0
    emails = d.get("userEmails") or []
    primary_email = emails[0] if emails else ""
    serial = d.get("serialNumber") or ""
    return (group, primary_email, serial)


def _table_columns(devices: list[dict], with_clients: bool, include_browser: bool):
    """Compute (headers, rows-as-tuples) for the survivor Mac table.

    Shared between the plain-text table renderer and the CSV writer so the
    column set stays identical across formats.
    """
    def row(d: dict) -> tuple:
        base: tuple = (
            ", ".join(d.get("userEmails") or []) or "-",
            device_id_cell(d),
        )
        if include_browser:
            base = base + (d.get("browser") or "-",)
        base = base + (
            classify_signals(d),
            d.get("serialNumber", "-"),
            # Decoded narrative when recognized; otherwise the raw Apple model
            # identifier flagged with "*" (see model_cell).
            model_cell(d),
            d.get("osVersion") or "-",
            d.get("hostname") or "-",
            d.get("assetTag", "-"),
            d.get("encryptionState", "-"),
            d.get("lastSyncTime", "-"),
        )
        if with_clients:
            return base + (", ".join(d.get("clientIds") or []) or "-",)
        return base

    headers: tuple = ("USER", "DEVICE_ID")
    if include_browser:
        headers = headers + ("BROWSER",)
    headers = headers + ("SIGNALS", "SERIAL", "MODEL", "OS_VERSION", "HOSTNAME", "ASSET_TAG", "ENCRYPTION", "LAST_SYNC")
    if with_clients:
        headers = headers + ("CLIENTS",)
    rows = [row(d) for d in devices]
    return headers, rows


def render_table(devices: list[dict], with_clients: bool, include_browser: bool) -> str:
    headers, rows = _table_columns(devices, with_clients, include_browser)
    return _format_plain(headers, rows)


def _format_plain(headers: Sequence[str], rows: Sequence[Sequence]) -> str:
    """Pretty-print headers + rows as a fixed-width column table."""
    widths = [
        max(len(str(r[i])) for r in (list(rows) + [list(headers)]))
        for i in range(len(headers))
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines.extend(fmt.format(*r) for r in rows)
    return "\n".join(lines)


def write_formatted(
    fmt: str,
    output_path: str | None,
    *,
    plain_text: str,
    rows_for_json: list[dict],
    csv_headers: Sequence[str],
    csv_rows: Sequence[Sequence],
) -> None:
    """Dispatch on `fmt` and write to stdout or `output_path`.

    Callers pre-compute the three representations (string for `plain`, dict
    list for `json`, header + row sequences for `csv`) and pass them in. Keeps
    the dispatcher trivial and lets each script wire its own column logic.
    """
    fh = open(output_path, "w", newline="") if output_path else sys.stdout
    try:
        if fmt == "plain":
            print(plain_text, file=fh)
        elif fmt == "json":
            json.dump(rows_for_json, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
        elif fmt == "csv":
            writer = csv.writer(fh)
            writer.writerow(csv_headers)
            for row in csv_rows:
                writer.writerow(row)
        else:
            raise ValueError(f"unknown format: {fmt}")
    finally:
        if output_path:
            fh.close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--format", choices=["plain", "json", "csv"], default="plain",
        help="Output format (default: plain). `json` mirrors the existing JSON "
             "structure; `csv` writes a header row and quote-escapes commas.",
    )
    p.add_argument(
        "--output", metavar="PATH",
        help="Write the formatted output to a file at PATH instead of stdout. "
             "--timing output continues to go to stderr.",
    )
    p.add_argument(
        "--view",
        choices=["USER_ASSIGNED_DEVICES", "COMPANY_INVENTORY"],
        default="USER_ASSIGNED_DEVICES",
        help="Which device set to list (default: USER_ASSIGNED_DEVICES, where "
             "Endpoint Verification Macs live).",
    )
    p.add_argument(
        "--last-sync-days", type=int, default=30,
        help="Drop devices whose lastSyncTime is older than N days (default: 30). "
             "This script's purpose is the active fleet; widen for occasional "
             "audits, but expect more quota pressure.",
    )
    p.add_argument(
        "--user", metavar="EMAIL",
        help="Restrict to devices associated with a single user (by email). "
             "Skips the tenant-wide devices.list call and the bulk "
             "deviceUsers.list call — issues only one targeted "
             "deviceUsers.list (server-side email filter where supported) and "
             "one batched devices.get for the user's device set. The fastest "
             "and cheapest way to look up one user's Macs.",
    )
    p.add_argument(
        "--include-browser", action="store_true",
        help="Add the BROWSER column (Chrome version per device from the EV "
             "signal block). Costs one extra devices.get call per survivor — "
             "off by default to keep the API-call footprint low. Worth turning "
             "on for ad-hoc audits where you want to see which Chrome versions "
             "are in the fleet.",
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

    devices = list(list_mac_devices(
        creds,
        view=args.view,
        with_clients=args.clients,
        last_sync_days=args.last_sync_days,
        include_browser=args.include_browser,
        user_email=args.user,
        timing=timing,
    ))
    # Surface unencrypted Macs at the top; encrypted ones at the bottom.
    devices.sort(key=encryption_sort_key)

    t = time.perf_counter()
    headers, rows = _table_columns(devices, args.clients, args.include_browser)
    plain_text = _format_plain(headers, rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(devices)} Mac device(s) "
            f"active in the last {args.last_sync_days} day(s) with a serial number."
        )
    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=devices,
        csv_headers=headers,
        csv_rows=rows,
    )
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
