#!/usr/bin/env python3
"""List Workspace sign-in events from the Admin SDK Reports `login` activity log.

Surfaces who signed in (or tried to), when, from which IP, and via which
method (`google_password`, `saml`, `oauth`, `unknown`), plus a `suspicious`
flag Google sets on risky sign-ins.

Each IP is annotated with its registered network owner (the `IP_OWNER` column),
resolved via RDAP and cached locally — see `ip_attribution.py`. This is on by
default; `--no-ip-attribution` disables it (no network calls). The first run
on a cold cache is slower while owners are looked up; later runs hit the cache.

**What this script does NOT include**: the browser user-agent string.
Login events in the Reports API don't carry a `user_agent` parameter — IP
is the closest "where from" identifier on this surface. If you need browser
attribution, see `list_mac_devices.py` (Cloud Identity Devices) for the
EV-equipped subset of machines; there's no per-sign-in browser data
available from Workspace audit logs.

Auth: keyless. Same pattern as the other reports — local gcloud ADC + IAM
signJwt to mint a DWD-impersonated admin token. Requires the DWD entry to
include `admin.reports.audit.readonly` (already set up for the token
report).
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

from googleapiclient.discovery import build

from ip_attribution import attribute_ips
from list_mac_devices import (
    _format_plain,
    build_credentials,
    render_location,
    write_formatted,
)

SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


def _param(event: dict, name: str) -> str:
    for p in event.get("parameters") or []:
        if p.get("name") == name:
            v = p.get("value")
            if v is None and p.get("boolValue") is not None:
                v = "true" if p["boolValue"] else "false"
            return v or ""
    return ""


def fetch_login_activity(
    creds, days: int, user_key: str, *, suspicious_only: bool = False,
):
    """Paginated activities.list against the `login` application.

    When `suspicious_only` is True, the Admin SDK's `filters` parameter pushes
    the is_suspicious==true predicate to the server — cuts pagination calls and
    response volume on high-login tenants. `--failures-only` stays a
    client-side filter because its "login_failure OR suspicious success"
    semantics don't translate to a single server-side filter.
    """
    svc = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    kwargs = dict(
        userKey=user_key,
        applicationName="login",
        startTime=start,
        maxResults=1000,
    )
    if suspicious_only:
        kwargs["filters"] = "is_suspicious==true"
    req = svc.activities().list(**kwargs)
    while req is not None:
        resp = req.execute()
        for item in resp.get("items", []):
            yield item
        req = svc.activities().list_next(req, resp)


SIGNIN_EVENTS = {"login_success", "login_failure"}
CHALLENGE_EVENTS = {"login_challenge", "login_verification"}


def flatten(
    activities,
    include_logout: bool,
    include_challenges: bool,
    failures_only: bool,
) -> list[dict]:
    """One row per (activity, event). No deduplication."""
    rows: list[dict] = []
    for activity in activities:
        user = (activity.get("actor") or {}).get("email") or ""
        time = (activity.get("id") or {}).get("time") or ""
        ip = activity.get("ipAddress") or ""
        location = render_location(activity.get("networkInfo") or {})
        for ev in activity.get("events") or []:
            name = ev.get("name") or ""
            if name in SIGNIN_EVENTS:
                pass
            elif name == "logout":
                if not include_logout:
                    continue
            elif name in CHALLENGE_EVENTS:
                if not include_challenges:
                    continue
            else:
                # Unknown / future event types — surface only when including
                # challenges, otherwise skip to keep the default view tight.
                if not include_challenges:
                    continue
            login_type = _param(ev, "login_type")
            suspicious = _param(ev, "is_suspicious") == "true"
            if failures_only and name != "login_failure" and not suspicious:
                continue
            rows.append({
                "user": user,
                "time": time,
                "event": name,
                "login_type": login_type,
                "suspicious": suspicious,
                "ip": ip,
                "location": location,
                "raw_event": ev,
            })
    return rows


HEADERS = (
    "USER", "TIME", "EVENT", "LOGIN_TYPE", "SUSPICIOUS", "IP", "IP_OWNER", "LOCATION"
)


def _table_columns(rows: list[dict]) -> list[tuple]:
    """Full-data row tuples (no truncation). Used directly for CSV; trimmed
    by `render_table` for plain output."""
    return [
        (
            r["user"] or "-",
            r["time"] or "-",
            r["event"] or "-",
            r["login_type"] or "-",
            "true" if r["suspicious"] else "-",
            r["ip"] or "-",
            r.get("ip_owner") or "-",
            r["location"] or "-",
        )
        for r in rows
    ]


def render_table(rows: list[dict]) -> str:
    def shrink(s: str, limit: int) -> str:
        return s if len(s) <= limit else s[: limit - 1] + "…"

    # Trim IPv6 (the IP column) at IPv6 max width for the plain table; full
    # value preserved in JSON / CSV output. OWNER passes through untrimmed.
    full = _table_columns(rows)
    trimmed = [
        (r[0], r[1], r[2], r[3], r[4], shrink(r[5], 39), r[6], r[7]) for r in full
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
        "--days", type=int, default=30,
        help="Lookback window in days (default: 30).",
    )
    p.add_argument(
        "--user",
        help="Restrict to a single user email (default: all users in tenant).",
    )
    p.add_argument(
        "--failures-only", action="store_true",
        help="Show only login_failure events plus any successes with is_suspicious=true.",
    )
    p.add_argument(
        "--suspicious-only", action="store_true",
        help="Show only events flagged is_suspicious=true (any event type). "
             "Applied server-side via the Reports API `filters` parameter, "
             "so this also reduces API call count and response volume.",
    )
    p.add_argument(
        "--include-logout", action="store_true",
        help="Include logout events (off by default — they double row count without sign-in-source info).",
    )
    p.add_argument(
        "--include-challenges", action="store_true",
        help="Include login_challenge / login_verification / other non-sign-in events.",
    )
    p.add_argument(
        "--no-ip-attribution", action="store_true",
        help="Skip OWNER enrichment (no RDAP lookups). By default each IP is "
             "annotated with its registered network owner via RDAP, cached "
             "locally; the first run on a fresh cache is slower.",
    )
    p.add_argument(
        "--refresh-ip-attribution", action="store_true",
        help="Bypass the cached owner for IPs seen this run and refetch them "
             "from RDAP (registration data is slow-changing, so rarely needed).",
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

    creds = build_credentials(sa_email, admin_email, SCOPES)
    activities = fetch_login_activity(
        creds, args.days, args.user or "all",
        suspicious_only=args.suspicious_only,
    )
    rows = flatten(
        activities,
        include_logout=args.include_logout,
        include_challenges=args.include_challenges,
        failures_only=args.failures_only,
    )
    rows.sort(key=lambda r: r["time"], reverse=True)

    # Annotate each row with the registered network owner of its source IP.
    # On by default; --no-ip-attribution skips all RDAP/network work.
    if args.no_ip_attribution:
        for r in rows:
            r["ip_owner"] = ""
            r["ip_attribution"] = None
    else:
        attribution = attribute_ips(
            (r["ip"] for r in rows),
            refresh=args.refresh_ip_attribution,
        )
        for r in rows:
            info = attribution.get(r["ip"]) if r["ip"] else None
            r["ip_owner"] = (info or {}).get("owner", "")
            r["ip_attribution"] = info

    plain_text = render_table(rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(rows)} sign-in event(s) "
            f"over the last {args.days} day(s)."
        )
    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=rows,
        csv_headers=HEADERS,
        csv_rows=_table_columns(rows),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
