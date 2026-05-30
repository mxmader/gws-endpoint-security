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

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import google.auth
from google.auth.transport.requests import AuthorizedSession
from googleapiclient.discovery import build

from list_mac_devices import build_credentials

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


def fetch_token_activity(creds, days: int, user_key: str):
    svc = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
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
        resp = req.execute()
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


def render_table(rows: list[dict]) -> str:
    def shrink(s: str, limit: int) -> str:
        return s if len(s) <= limit else s[: limit - 1] + "…"

    headers = ("USER", "APP_NAME", "EVENT", "CLIENT_TYPE", "CLIENT_ID", "LAST_EVENT")
    tabular = [
        (
            r["user"] or "-",
            shrink(r["app_name"] or "-", 40),
            r["event_name"] or "-",
            r["client_type"] or "-",
            shrink(r["client_id"] or "-", 60),
            r["time"] or "-",
        )
        for r in rows
    ]
    widths = [
        max(len(str(row[i])) for row in (tabular + [headers]))
        for i in range(len(headers))
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines.extend(fmt.format(*r) for r in tabular)
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true", help="Dump raw JSON instead of a table.")
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
    args = p.parse_args()

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Reports API read privilege>", file=sys.stderr)
        return 2

    self_client_id = get_sa_oauth_client_id(sa_email) if args.exclude_self else ""

    creds = build_credentials(sa_email, admin_email, SCOPES)
    activities = fetch_token_activity(creds, args.days, args.user or "all")
    latest = aggregate(activities, key_by_app_name=args.most_recent_apps_for_user)

    rows = sorted(latest.values(), key=lambda r: r["time"], reverse=True)
    if not args.show_revoked:
        rows = [r for r in rows if r["event_name"] != "revoke"]
    if self_client_id:
        rows = [r for r in rows if r["client_id"] != self_client_id]

    if args.json:
        json.dump(rows, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_table(rows))
        print(f"\n{len(rows)} app authorization(s) over the last {args.days} day(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
