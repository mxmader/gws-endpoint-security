#!/usr/bin/env python3
"""Per-user authentication-factor rollup from the Admin SDK Reports `login` log.

`list_signins.py` answers *who signed in from where*. This script answers
*which authentication factors each user actually relies on, and who is still
on weak or no 2-step verification*.

The factor data lives in the `login_challenge` / `login_verification` events
(which `list_signins.py` filters out by default), inside a multi-value
parameter `login_challenge_method` — e.g. `["password", "security_key"]`.
We classify each method into a friendly name and a strength tier (passkey /
security key = strong; Google prompt / TOTP = medium; SMS / backup codes =
weak; password-only / no second factor = none), then roll the window up to one
row per user: the distinct factors they used, their *weakest* factor, whether
any second factor was ever seen, sign-in counts, and last-seen time.

Each user is enriched with Directory API 2-step-verification posture
(`isEnrolledIn2Sv`, `isEnforcedIn2Sv`) so the report distinguishes
"enrolled but using a weak factor" from "not enrolled at all". Rows sort
worst-posture-first: not-enrolled / password-only users float to the top,
users with all-strong factors sink, and users who never signed in during the
window (can't assess) land last.

Caveats:
- A *failed* challenge never grants a factor — a failed security-key attempt
  must not make a user look like they use security keys.
- `saml` logins show the factor as not visible here: the real second factor
  lives at the external IdP, outside Workspace's view.

Auth: keyless DWD, same pattern as the other reports. Requires DWD scopes
`admin.reports.audit.readonly` (Reports) and `admin.directory.user.readonly`
(Users) — both already in the repo's DWD entry — and the matching Admin
API → Reports (Read) + Users (Read) privileges on WORKSPACE_ADMIN_EMAIL.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from list_mac_devices import _execute, _format_plain, build_credentials, write_formatted
from list_signins import _param, fetch_login_activity

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

# Strength tiers. Lower int = weaker = surfaced first (matches the device
# scripts' "worst posture first" convention).
STRENGTH_NONE = 0    # password-only / no real second factor
STRENGTH_WEAK = 1    # phishable, knowledge / SMS / one-time printed
STRENGTH_MEDIUM = 2  # push / TOTP — phishable but device-bound
STRENGTH_STRONG = 3  # passkey / FIDO2 — phishing-resistant

# Raw `login_challenge_method` value -> (friendly name, strength tier).
FACTOR_MAP: dict[str, tuple[str, int]] = {
    # --- phishing-resistant (STRONG) ---
    "passkey": ("Passkey", STRENGTH_STRONG),
    "security_key": ("Security key (FIDO2)", STRENGTH_STRONG),
    "security_key_otp": ("Security key (OTP)", STRENGTH_STRONG),
    "cross_device": ("Cross-device passkey", STRENGTH_STRONG),
    "device_prompt": ("Device prompt", STRENGTH_STRONG),
    # --- device-bound but phishable (MEDIUM) ---
    "google_prompt": ("Google prompt (push)", STRENGTH_MEDIUM),
    "google_authenticator": ("Authenticator (TOTP)", STRENGTH_MEDIUM),
    "offline_otp": ("Offline OTP (TOTP)", STRENGTH_MEDIUM),
    # --- weak: knowledge-based / SMS / one-time printed ---
    "backup_code": ("Backup code", STRENGTH_WEAK),
    "rescue_code": ("Rescue code", STRENGTH_WEAK),
    "idv_preregistered_phone": ("SMS/voice (registered)", STRENGTH_WEAK),
    "idv_any_phone": ("SMS/voice (any)", STRENGTH_WEAK),
    "idv_preregistered_email": ("Email verification", STRENGTH_WEAK),
    "idv_any_email": ("Email verification (any)", STRENGTH_WEAK),
    # --- password / no second factor (NONE) ---
    "password": ("Password", STRENGTH_NONE),
    # SAML's real factor lives at the external IdP — invisible here, so NONE,
    # not "strong". Flag it; don't credit it.
    "saml": ("SAML (external IdP)", STRENGTH_NONE),
    # --- challenge plumbing, classified for transparency ---
    "captcha": ("CAPTCHA", STRENGTH_NONE),
    "recaptcha": ("reCAPTCHA", STRENGTH_NONE),
    "none": ("None", STRENGTH_NONE),
    "other": ("Other", STRENGTH_NONE),
}

# Methods that are challenge plumbing, not real auth factors — excluded from
# the "distinct factors used" set and from weakest-factor computation.
NON_FACTOR_METHODS = frozenset({"captcha", "recaptcha", "none", "other"})

# Methods that count as a genuine SECOND factor (evidence 2SV actually ran).
SECOND_FACTOR_METHODS = (
    frozenset(FACTOR_MAP) - NON_FACTOR_METHODS - {"password", "saml"}
)


def classify_method(raw: str) -> tuple[str, int]:
    """Map a raw method to (friendly, strength). Unknown -> ('Other (<raw>)', NONE)."""
    key = (raw or "").strip().lower()
    if key in FACTOR_MAP:
        return FACTOR_MAP[key]
    return (f"Other ({raw})" if raw else "Unknown", STRENGTH_NONE)


def _param_multi(event: dict, name: str) -> list[str]:
    """Read a multi-valued event parameter as a list of strings.

    RUNTIME-VERIFY: the Reports API has been observed to encode multi-valued
    params more than one way depending on discovery-doc version:
      - p["multiValue"]    -> ["password", "security_key"]   (plain strings)
      - p["multiStrValue"] -> ["password", "security_key"]   (alias)
      - p["multiValue"]    -> [{"value": "password"}, ...]    (dict-wrapped)
    Check all of them and coerce every element to str. Falls back to the
    single-valued forms (value / boolValue) wrapped in a 1-list so callers can
    treat every param uniformly. Built so it cannot crash on any shape.
    """
    for p in event.get("parameters") or []:
        if p.get("name") != name:
            continue
        for key in ("multiValue", "multiStrValue"):
            raw = p.get(key)
            if raw:
                out: list[str] = []
                for el in raw:
                    if isinstance(el, dict):
                        v = el.get("value")
                        if v is not None:
                            out.append(str(v))
                    elif el is not None:
                        out.append(str(el))
                return out
        v = p.get("value")
        if v is not None:
            return [str(v)]
        if p.get("boolValue") is not None:
            return ["true" if p["boolValue"] else "false"]
        return []
    return []


def rollup_factors(activities, *, count_failed: bool = False) -> dict[str, dict]:
    """Aggregate login activities into one stat dict per actor email.

    Returns {email_lower -> {user, factors, signin_count, any_second_factor,
    suspicious_count, last_seen}} where `factors` is {friendly_name -> strength}
    for real factors only.

    Only PASSED challenges and successful logins contribute factors: a failed
    challenge never grants a factor. `signin_count` is "qualifying auth events"
    (successful logins, plus failures when `count_failed`), not distinct
    sessions — there's no reliable cross-event session key.
    """
    stats: dict[str, dict] = {}
    for activity in activities:
        actor_email = (activity.get("actor") or {}).get("email") or ""
        email = actor_email.lower()
        if not email:
            continue
        t = (activity.get("id") or {}).get("time") or ""
        s = stats.get(email)
        if s is None:
            s = stats[email] = {
                "user": actor_email,
                "factors": {},
                "signin_count": 0,
                "any_second_factor": False,
                "suspicious_count": 0,
                "last_seen": "",
            }

        suspicious_activity = False
        touched = False
        for ev in activity.get("events") or []:
            name = ev.get("name") or ""
            status = _param(ev, "login_challenge_status")
            passed = "fail" not in status.lower() and name != "login_failure"
            if _param(ev, "is_suspicious") == "true":
                suspicious_activity = True

            if name == "login_success" and passed:
                s["signin_count"] += 1
                touched = True
            elif name == "login_failure" and count_failed:
                s["signin_count"] += 1
                touched = True

            if passed:
                for raw in _param_multi(ev, "login_challenge_method"):
                    key = (raw or "").strip().lower()
                    if not key:
                        continue
                    friendly, strength = classify_method(raw)
                    if key in NON_FACTOR_METHODS:
                        continue
                    s["factors"][friendly] = strength
                    if key in SECOND_FACTOR_METHODS:
                        s["any_second_factor"] = True
                    touched = True
                if _param(ev, "is_second_factor") == "true":
                    s["any_second_factor"] = True
                    touched = True

        if suspicious_activity:
            s["suspicious_count"] += 1
        if touched and t > s["last_seen"]:
            s["last_seen"] = t
    return stats


def fetch_users_2sv(svc, *, include_suspended: bool, user_email: str | None) -> list[dict]:
    """Directory users with 2SV enrollment fields.

    Single-user path uses `users().get` (1 quota unit, no pagination) and
    tolerates a 404 (e.g. an ex-employee who still appears in the login log)
    by returning []. Tenant path paginates `users().list`.
    """
    fields_user = (
        "primaryEmail,aliases,suspended,lastLoginTime,"
        "isEnrolledIn2Sv,isEnforcedIn2Sv,name/fullName"
    )
    if user_email:
        try:
            return [_execute(svc.users().get(userKey=user_email, fields=fields_user))]
        except HttpError as exc:
            if exc.resp.status == 404:
                return []
            raise

    out: list[dict] = []
    kwargs = dict(
        customer="my_customer",
        maxResults=500,
        fields=f"users({fields_user}),nextPageToken",
    )
    if not include_suspended:
        kwargs["query"] = "isSuspended=false"
    req = svc.users().list(**kwargs)
    while req is not None:
        resp = _execute(req)
        out.extend(resp.get("users", []))
        req = svc.users().list_next(req, resp)
    return out


def _user_addresses(u: dict) -> set[str]:
    """Lowercased primaryEmail + every alias (dict or bare-string shape)."""
    addrs = {(u.get("primaryEmail") or "").lower()}
    for a in u.get("aliases") or []:
        if isinstance(a, dict):
            addrs.add((a.get("alias") or "").lower())
        elif isinstance(a, str):
            addrs.add(a.lower())
    addrs.discard("")
    return addrs


def _merge_stats(a: dict | None, b: dict) -> dict:
    """Combine two rollup stat dicts (same user signed in under >1 address)."""
    if a is None:
        return {**b, "factors": dict(b["factors"])}
    a["factors"].update(b["factors"])
    a["signin_count"] += b["signin_count"]
    a["any_second_factor"] = a["any_second_factor"] or b["any_second_factor"]
    a["suspicious_count"] += b["suspicious_count"]
    if b["last_seen"] > a["last_seen"]:
        a["last_seen"] = b["last_seen"]
    return a


def _make_row(*, user, in_directory, enrolled, enforced, name, stat) -> dict:
    factors = (stat or {}).get("factors") or {}
    # "Weakest factor" ranks the weakest *second* factor: password and SAML are
    # the primary factor (strength NONE), and since everyone signs in with one,
    # including them would collapse every user to "Password". A user with no
    # second factor is password-only — the worst posture, weakest = "Password".
    second = {f: s for f, s in factors.items() if s > STRENGTH_NONE}
    if second:
        weakest_factor, weakest_strength = min(
            second.items(), key=lambda kv: (kv[1], kv[0])
        )
    elif factors:
        weakest_factor, weakest_strength = min(
            factors.items(), key=lambda kv: (kv[1], kv[0])
        )
    else:
        weakest_factor, weakest_strength = "", None
    return {
        "user": user,
        "in_directory": in_directory,
        "enrolled_2sv": enrolled,
        "enforced_2sv": enforced,
        "name": name,
        "factor_set": sorted(factors),
        "weakest_factor": weakest_factor,
        "weakest_strength": weakest_strength,
        "any_second_factor": (stat or {}).get("any_second_factor", False),
        "signin_count": (stat or {}).get("signin_count", 0),
        "suspicious_count": (stat or {}).get("suspicious_count", 0),
        "last_seen": (stat or {}).get("last_seen", ""),
    }


def build_rows(stats: dict[str, dict], dir_users: list[dict]) -> list[dict]:
    """Join the per-user rollup with directory posture into the four populations.

    1. In directory (active or inactive) — real 2SV columns.
    2. Signed in but not in directory (ex-employee / external) — 2SV unknown.
    """
    rows: list[dict] = []
    consumed: set[str] = set()
    for u in dir_users:
        merged: dict | None = None
        for addr in _user_addresses(u):
            s = stats.get(addr)
            if s is not None and addr not in consumed:
                merged = _merge_stats(merged, s)
                consumed.add(addr)
        rows.append(_make_row(
            user=u.get("primaryEmail") or "",
            in_directory=True,
            enrolled=u.get("isEnrolledIn2Sv"),
            enforced=u.get("isEnforcedIn2Sv"),
            name=(u.get("name") or {}).get("fullName") or "",
            stat=merged,
        ))
    for email, s in stats.items():
        if email in consumed:
            continue
        rows.append(_make_row(
            user=s["user"],
            in_directory=False,
            enrolled=None,
            enforced=None,
            name="",
            stat=s,
        ))
    return rows


def _posture_group(row: dict) -> int:
    """0 not-enrolled / no 2nd factor, 1 weak, 2 medium, 3 strong,
    4 in directory but no sign-ins in window (can't assess)."""
    if row["in_directory"] and row["signin_count"] == 0:
        return 4
    if row["enrolled_2sv"] is False or not row["any_second_factor"]:
        return 0
    # Reaching here means a second factor was seen. Rank by its strength;
    # unknown strength (flagged but method not captured) stays conservative.
    weakest = row["weakest_strength"]
    if weakest is None or weakest <= STRENGTH_WEAK:
        return 1
    if weakest == STRENGTH_MEDIUM:
        return 2
    return 3


def _is_weak(row: dict) -> bool:
    """Assessable user whose weakest real factor is WEAK or NONE."""
    if row["signin_count"] == 0:
        return False
    if not row["any_second_factor"]:
        return True
    return row["weakest_strength"] is None or row["weakest_strength"] <= STRENGTH_WEAK


HEADERS = (
    "USER", "ENROLLED_2SV", "ENFORCED_2SV", "WEAKEST_FACTOR", "FACTORS_USED",
    "2ND_FACTOR_SEEN", "SIGNINS", "SUSPICIOUS", "LAST_SEEN",
)


def _yn(v) -> str:
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return "?"


def _table_columns(rows: list[dict]) -> list[tuple]:
    """Full-data row tuples (no truncation). Used directly for CSV; trimmed by
    `render_table` for plain output."""
    return [
        (
            r["user"] or "-",
            _yn(r["enrolled_2sv"]),
            _yn(r["enforced_2sv"]),
            r["weakest_factor"] or "-",
            ", ".join(r["factor_set"]) or "-",
            "yes" if r["any_second_factor"] else "no",
            str(r["signin_count"]),
            str(r["suspicious_count"]) if r["suspicious_count"] else "-",
            r["last_seen"] or "-",
        )
        for r in rows
    ]


def render_table(rows: list[dict]) -> str:
    def shrink(s: str, limit: int) -> str:
        return s if len(s) <= limit else s[: limit - 1] + "…"

    # Trim FACTORS_USED (col 4) for the plain table; full value kept in JSON/CSV.
    full = _table_columns(rows)
    trimmed = [
        (r[0], r[1], r[2], r[3], shrink(r[4], 48), r[5], r[6], r[7], r[8])
        for r in full
    ]
    return _format_plain(HEADERS, trimmed)


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
        "--days", type=int, default=30,
        help="Lookback window in days (default: 30).",
    )
    p.add_argument(
        "--user",
        help="Restrict to a single user email (default: all users in tenant).",
    )
    p.add_argument(
        "--include-suspended", action="store_true",
        help="Include suspended users on the directory side (off by default).",
    )
    p.add_argument(
        "--unenrolled-only", action="store_true",
        help="Show only users with isEnrolledIn2Sv == false.",
    )
    p.add_argument(
        "--weak-only", action="store_true",
        help="Show only users whose weakest factor used is weak or password-only "
             "(the 'fix these first' view). Combined with --unenrolled-only, both apply.",
    )
    p.add_argument(
        "--count-failed", action="store_true",
        help="Include failed challenges/logins in sign-in counts (off by default). "
             "Failed challenges never grant a factor regardless of this flag.",
    )
    p.add_argument(
        "--timing", action="store_true",
        help="Print a per-phase wall-clock breakdown to stderr after the run.",
    )
    args = p.parse_args()

    if args.days < 1:
        print("--days must be >= 1", file=sys.stderr)
        return 2

    try:
        sa_email = os.environ["SA_EMAIL"]
        admin_email = os.environ["WORKSPACE_ADMIN_EMAIL"]
    except KeyError as exc:
        print(f"Missing required env var: {exc.args[0]}", file=sys.stderr)
        print("  export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com", file=sys.stderr)
        print("  export WORKSPACE_ADMIN_EMAIL=<admin with Reports (Read) + Users (Read) privileges>", file=sys.stderr)
        return 2

    timing: dict[str, float] = {}
    creds = build_credentials(sa_email, admin_email, SCOPES)
    t = time.perf_counter()
    creds.refresh(Request())  # refresh once so the parallel threads don't race it
    timing["auth refresh"] = time.perf_counter() - t

    directory_svc = build(
        "admin", "directory_v1",
        credentials=creds, cache_discovery=False, static_discovery=True,
    )

    # Parallel: Reports login activity (+rollup) and Directory users.list. They
    # run against different APIs so there's no shared httplib2 instance.
    def _factors():
        t0 = time.perf_counter()
        activities = fetch_login_activity(creds, args.days, args.user or "all")
        out = rollup_factors(activities, count_failed=args.count_failed)
        return out, time.perf_counter() - t0

    def _users():
        t0 = time.perf_counter()
        out = fetch_users_2sv(
            directory_svc,
            include_suspended=args.include_suspended,
            user_email=args.user,
        )
        return out, time.perf_counter() - t0

    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_factors = pool.submit(_factors)
        f_users = pool.submit(_users)
        stats, factors_elapsed = f_factors.result()
        dir_users, users_elapsed = f_users.result()
    timing["[parallel] login activity + rollup"] = factors_elapsed
    timing["[parallel] users.list"] = users_elapsed
    timing["[parallel] section wall"] = time.perf_counter() - t

    rows = build_rows(stats, dir_users)
    if args.unenrolled_only:
        rows = [r for r in rows if r["enrolled_2sv"] is False]
    if args.weak_only:
        rows = [r for r in rows if _is_weak(r)]
    rows.sort(key=lambda r: (_posture_group(r), (r["user"] or "").lower()))

    # Footer counts mirror the sort groups (0..4) so they read in table order.
    groups = [0, 0, 0, 0, 0]
    for r in rows:
        groups[_posture_group(r)] += 1

    plain_text = render_table(rows)
    if args.format == "plain" and not args.output:
        plain_text = (
            f"{plain_text}\n\n{len(rows)} user(s): "
            f"{groups[0]} not enrolled or no 2nd factor, "
            f"{groups[1]} weak-factor, {groups[2]} medium-factor, "
            f"{groups[3]} strong-factor, "
            f"{groups[4]} inactive (no sign-ins in {args.days}d)."
        )

    write_formatted(
        args.format, args.output,
        plain_text=plain_text,
        rows_for_json=rows,
        csv_headers=HEADERS,
        csv_rows=_table_columns(rows),
    )

    if args.timing:
        width = max(len(k) for k in timing) if timing else 0
        print("\n--- timing (stderr) ---", file=sys.stderr)
        for k, v in timing.items():
            print(f"  {k:<{width}}  {v*1000:8.1f} ms", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
