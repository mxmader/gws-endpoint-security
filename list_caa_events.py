#!/usr/bin/env python3
"""List Context-Aware Access events correlated with device records.

Reads the Admin SDK Reports `context_aware_access` activity log and surfaces
events where a named access level appears in either CAA_ACCESS_LEVEL_SATISFIED
or CAA_ACCESS_LEVEL_UNSATISFIED. Each row is joined against the matching
Cloud Identity Device record (when CAA_DEVICE_ID resolves), adding the same
columns `list_mac_devices.py` produces — SIGNALS, SERIAL, MODEL (decoded via
mac_models.json), OS_VERSION, HOSTNAME, ASSET_TAG, ENCRYPTION, LAST_SYNC.

OUTCOME column values:

- `satisfied` — the named access level passed at decision time. The denial
  was caused by some *other* policy condition failing.
- `unsatisfied` — the named access level was the failing condition.

CAA_DEVICE_ID format note: the Reports API typically emits these with an
extra leading `-` that is NOT part of the underlying Cloud Identity device
ID — the Admin Console strips it transparently, this script does the same
in `_normalize_device_name`. Lookup failures (400, 404) blank out the
device columns rather than failing the run.

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

from list_mac_devices import (
    _execute,
    _format_plain,
    _run_batch,
    build_credentials,
    classify_signals,
    decode_model,
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
                "blocked_api": _param(ev, "BLOCKED_API_ACCESS"),
                "device_state": _param(ev, "CAA_DEVICE_STATE"),
                "device_risks": device_risks,
                "outcome": outcome,
                "event_name": ev.get("name") or "",
            })
    return rows


def _normalize_device_name(raw: str) -> str:
    """`CAA_DEVICE_ID` may be a bare ID or a full resource name; normalize.

    Empirical quirk: the Reports API often emits CAA_DEVICE_ID with an extra
    leading `-` that is NOT part of the underlying Cloud Identity device ID.
    The Admin Console strips it transparently; the public REST API does not
    (it returns 400 because `devices/-...` collides with the wildcard-parent
    pattern). Strip the leading dash before constructing the resource name.
    """
    if not raw:
        return ""
    if raw.startswith("devices/"):
        return raw
    if raw.startswith("-"):
        raw = raw[1:]
    return f"devices/{raw}"


def fetch_devices(
    creds, device_ids: set[str], *, debug: bool = False,
) -> dict[str, dict]:
    """Batched devices.get for the set of CAA-referenced device IDs.

    Keys the result by the **raw** CAA_DEVICE_ID string so the caller can
    look up by what's in the event.

    Both 404 and 400 are silently tolerated. The CAA_DEVICE_ID format is not
    documented and empirically does not always match a Cloud Identity Device
    resource ID — many values look like EV device fingerprints (43-char
    base64url) which the API rejects with 400 ("invalid argument"). Either
    status means "can't resolve to a Cloud Identity Device"; the caller
    renders the device columns as empty for those rows (no fallback —
    preserving the per-device semantics of CAA decisions).

    When `debug=True`, the call is issued sequentially (one request at a
    time, not batched) and each request URI + response status is logged to
    stderr. Useful for diagnosing correlation failures.
    """
    if not device_ids:
        return {}
    svc = build(
        "cloudidentity", "v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )
    id_list = sorted(device_ids)

    if debug:
        result: dict[str, dict] = {}
        for did in id_list:
            req = svc.devices().get(name=_normalize_device_name(did))
            print(f"[debug] GET {req.uri}", file=sys.stderr)
            try:
                resp = req.execute()
                print(f"[debug]   -> 200 OK (resolved)", file=sys.stderr)
                result[did] = resp
            except HttpError as exc:
                status = getattr(getattr(exc, "resp", None), "status", "?")
                print(f"[debug]   -> {status}: {exc}", file=sys.stderr)
        return result

    factories: dict[str, Callable[[], object]] = {
        f"d{i}": (lambda did=did: svc.devices().get(name=_normalize_device_name(did)))
        for i, did in enumerate(id_list)
    }
    responses = _run_batch(svc, factories, ignore_statuses={400, 404})
    return {
        id_list[int(rid[1:])]: resp
        for rid, resp in responses.items()
        if resp
    }


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
    "TIME", "USER", "DEVICE_ID", "APP", "BLOCKED_API", "DEVICE_STATE",
    "DEVICE_RISKS", "OUTCOME",
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
            r.get("blocked_api") or "-",
            r.get("device_state") or "-",
            ", ".join(r.get("device_risks") or []) or "-",
            r.get("outcome") or "-",
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
            shrink(r[4], 50),    # BLOCKED_API
            r[5],                # DEVICE_STATE
            shrink(r[6], 40),    # DEVICE_RISKS
            r[7],                # OUTCOME
            r[8],                # SIGNALS
            r[9],                # SERIAL
            shrink(r[10], 40),   # MODEL (decoded names can run long)
            r[11], r[12], r[13], r[14], r[15],
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
        help="Issue device.get calls sequentially (not batched) and log each "
             "request URI + response status code to stderr. Use to diagnose "
             "CAA-to-Cloud-Identity device-ID correlation failures.",
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
    unique_device_ids = {r["device_id"] for r in rows if r.get("device_id")}
    device_by_id = fetch_devices(creds, unique_device_ids, debug=args.debug)
    if args.timing:
        timing[f"devices.get batched (n_requested={len(unique_device_ids)}, n_resolved={len(device_by_id)})"] = (
            time.perf_counter() - t
        )

    attach_device_fields(rows, device_by_id)
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
