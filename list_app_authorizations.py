#!/usr/bin/env python3
"""List apps each Workspace user has OAuth-authorized, via Admin SDK Reports.

Reads the `token` application activity log (admin.googleapis.com → reports_v1),
which records every OAuth grant or revoke against the tenant — with both the
OAuth client_id and a Google-curated friendly app_name ("Google Drive for
Desktop", "Slack", etc.). For each (user, client_id) pair we surface the most
recent event in the lookback window; revoked apps are dropped unless
--show-revoked is set.

Auth: keyless. Uses your local gcloud ADC + the IAM signJwt API to mint a
domain-wide-delegated access token impersonating WORKSPACE_ADMIN_EMAIL. The
DWD entry must include the admin.reports.audit.readonly scope.
"""
from __future__ import annotations

import time
_T_MODULE_START = time.perf_counter()

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

import google.auth
from google.auth.transport.requests import AuthorizedSession, Request
from googleapiclient.discovery import build

from list_mac_devices import _format_plain, build_credentials, write_formatted

SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


def get_sa_oauth_client_id(sa_email: str) -> str:
    """Look up the SA's numeric oauth2ClientId via the IAM API using local ADC.

    The same value DWD uses as the SA's Client ID, and the value Google records
    in `token` activity events whenever the SA itself is granted scopes.
    """
    source_creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/iam"],
    )
    session = AuthorizedSession(source_creds)
    url = f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}"
    r = session.get(url)
    r.raise_for_status()
    return r.json().get("oauth2ClientId", "")


def _param(event: dict, name: str) -> str:
    for p in event.get("parameters") or []:
        if p.get("name") == name:
            return p.get("value") or ""
    return ""


def fetch_token_activity(
    creds, days: int, user_key: str, *, page_log: list[float] | None = None,
):
    """Paginated activities.list against the `token` application.

    Pass `page_log` to capture per-page wall-clock seconds; the caller can
    derive page count + min/max/avg latency for diagnostics.
    """
    svc = build(
        "admin", "reports_v1",
        credentials=creds,
        cache_discovery=False,
        static_discovery=True,
    )
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    req = svc.activities().list(
        userKey=user_key,
        applicationName="token",
        startTime=start,
        maxResults=1000,
    )
    while req is not None:
        t0 = time.perf_counter()
        resp = req.execute()
        if page_log is not None:
            page_log.append(time.perf_counter() - t0)
        for item in resp.get("items", []):
            yield item
        req = svc.activities().list_next(req, resp)


def aggregate(activities, key_by_app_name: bool = False) -> dict[tuple[str, str], dict]:
    """Return {(user_email, key): latest_event_info}.

    key is `client_id` by default (one row per distinct OAuth client) or
    `app_name` when key_by_app_name=True (one row per app, most recent
    client_id used by that user retained).
    """
    latest: dict[tuple[str, str], dict] = {}
    for activity in activities:
        user = (activity.get("actor") or {}).get("email") or ""
        time = (activity.get("id") or {}).get("time") or ""
        for ev in activity.get("events") or []:
            client_id = _param(ev, "client_id")
            if not client_id:
                continue
            app_name = _param(ev, "app_name")
            key = (user, app_name) if key_by_app_name else (user, client_id)
            existing = latest.get(key)
            if existing and existing["time"] >= time:
                continue
            latest[key] = {
                "user": user,
                "client_id": client_id,
                "app_name": app_name,
                "client_type": _param(ev, "client_type"),
                "scope": _param(ev, "scope"),
                "event_name": ev.get("name") or "",
                "time": time,
            }
    return latest


HEADERS = ("USER", "APP_NAME", "EVENT", "CLIENT_TYPE", "CLIENT_ID", "LAST_EVENT")


def _table_columns(rows: list[dict]) -> list[tuple]:
    """Full-data row tuples (no truncation). Used directly for CSV; trimmed
    by `render_table` for plain output."""
    return [
        (
            r["user"] or "-",
            r["app_name"] or "-",
            r["event_name"] or "-",
            r["client_type"] or "-",
            r["client_id"] or "-",
            r["time"] or "-",
        )
        for r in rows
    ]


def render_table(rows: list[dict]) -> str:
    def shrink(s: str, limit: int) -> str:
        return s if len(s) <= limit else s[: limit - 1] + "…"

    # Apply terminal-width-friendly truncation to APP_NAME (col 1) and CLIENT_ID
    # (col 4) — full values are preserved in JSON / CSV output via _table_columns.
    full = _table_columns(rows)
    trimmed = [
        (r[0], shrink(r[1], 40), r[2], r[3], shrink(r[4], 60), r[5])
        for r in full
    ]
    return _format_plain(HEADERS, trimmed)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--format", choices=["plain", "json", "csv"], default="plain",
        help="Output format (default: plain). `json` mirrors the previous "
             "`--json` shape; `csv` writes a header row and quote-escapes commas.",
    )
    p.add_argument(
        "--output", metavar="PATH",
        help="Write the formatted output to a file at PATH instead of stdout.",
    )
    p.add_argument(
        "--days", type=int, default=180,
        help="Lookback window in days (default: 180; Admin Reports retention is ~6 months).",
    )
    p.add_argument(
        "--user",
        help="Restrict to a single user email (default: all users in tenant).",
    )
    p.add_argument(
        "--show-revoked", action="store_true",
        help="Include apps whose most-recent event in the window is `revoke`.",
    )
    p.add_argument(
        "--exclude-self", action="store_true",
        help="Drop the meta-event where the service account itself was "
             "granted scopes via DWD (its own oauth2ClientId). Requires local "
             "ADC to have iam.serviceAccounts.get on the SA.",
    )
    p.add_argument(
        "--most-recent-apps-for-user", action="store_true",
        help="Collapse to one row per (user, app_name) by keeping the most "
             "recent client_id used by that user for that app. Tightens the "
             "table at the cost of distinct-OAuth-client visibility.",
    )
    p.add_argument(
        "--timing", action="store_true",
        help="Print a per-phase wall-clock breakdown to stderr after the run, "
             "including pagination page count and per-page latency stats.",
    )
    args = p.parse_args()

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Reports API read privilege>", file=sys.stderr)
        return 2

    timing: dict[str, float] = {}
    page_log: list[float] = []
    t_main_start = time.perf_counter()
    if args.timing:
        timing["module import (post 'import time')"] = t_main_start - _T_MODULE_START

    self_client_id = get_sa_oauth_client_id(sa_email) if args.exclude_self else ""
    if args.timing:
        timing["get_sa_oauth_client_id" if args.exclude_self else "(skipped) get_sa_oauth_client_id"] = (
            time.perf_counter() - t_main_start
        )

    t = time.perf_counter()
    creds = build_credentials(sa_email, admin_email, SCOPES)
    if args.timing:
        timing["build_credentials (local)"] = time.perf_counter() - t

    # Force the signJwt + token-exchange RTTs to happen NOW so they show up as
    # their own phase, rather than folding into the first activities.list call.
    t = time.perf_counter()
    creds.refresh(Request())
    if args.timing:
        timing["auth refresh (signJwt + token)"] = time.perf_counter() - t

    t = time.perf_counter()
    activities = fetch_token_activity(
        creds, args.days, args.user or "all",
        page_log=page_log if args.timing else None,
    )
    latest = aggregate(activities, key_by_app_name=args.most_recent_apps_for_user)
    if args.timing:
        timing[f"activities.list + aggregate (pages={len(page_log)})"] = (
            time.perf_counter() - t
        )

    rows = sorted(latest.values(), key=lambda r: r["time"], reverse=True)
    if not args.show_revoked:
        rows = [r for r in rows if r["event_name"] != "revoke"]
    if self_client_id:
        rows = [r for r in rows if r["client_id"] != self_client_id]

    plain_text = render_table(rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(rows)} app authorization(s) "
            f"over the last {args.days} day(s)."
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
        width = max(len(k) for k in timing)
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
        print(f"  {'-' * width}  --------", file=sys.stderr)
        if page_log:
            print(
                f"  {'per-page latency':<{width}}  "
                f"n={len(page_log)} min={min(page_log)*1000:.0f}ms "
                f"max={max(page_log)*1000:.0f}ms "
                f"avg={(sum(page_log)/len(page_log))*1000:.0f}ms "
                f"total={sum(page_log)*1000:.0f}ms",
                file=sys.stderr,
            )
        print(f"  {'wall (post import time)':<{width}}  {wall*1000:8.1f} ms", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
