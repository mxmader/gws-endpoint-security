# How device data reaches Cloud Identity

The Cloud Identity Devices API doesn't expose a single "source of truth" per
device. Instead it accumulates one **Device record per reporting agent** that
registers under a managed user's identity, and merges whatever signals each
agent is capable of collecting. Different agents have different visibility,
so the field set per Device record is essentially a fingerprint of who
reported it.

These notes are empirically derived against a real Business Plus tenant on
2026-05-29 — not from Google docs — so they should be treated as observation,
not specification.

## The reporting agents we've seen

### Signed-in managed Chrome (browser-only signals)

Any Chrome session signed into a managed Workspace identity is enough to push
basic device signals to Cloud Identity, as long as at least one first-party
Google extension is active. That can be **Endpoint Verification**, but it can
also just be **Google Docs Offline**, the Drive web client, or another
first-party Workspace extension — they all carry the same Chrome-managed
identity signal. There's no requirement to install Endpoint Verification
specifically for these signals to show up.

What this channel reports:
- `encryptionState` — FileVault status (from browser-visible system info)
- `model` — precise model identifier (e.g. `Mac16,5`)
- `manufacturer` — e.g. `Apple Inc.`
- `osVersion` — e.g. `MacOS 26.5.0`
- `ownerType` — `BYOD` or company

What this channel does **not** report:
- `serialNumber`
- `hostname`

Admin Console prerequisite: **Devices → Mobile and endpoints → Settings →
Universal settings → Endpoint verification → "Collect device signals…"** must
be ON for the user's OU. Without it, the browser signals never leave the
client.

### Endpoint Verification extension + native helper (browser + hardware)

EV's native helper is an optional `.pkg` you install on the Mac alongside the
Chrome extension. The extension alone behaves like any other first-party
Google extension (browser-only signals). The helper unlocks the hardware
identifiers that the browser sandbox can't read.

Field set is the union of the browser-only set plus:
- `serialNumber`
- `hostname` (sometimes)

This is the only channel from which Cloud Identity learns both `encryptionState`
*and* `serialNumber` for the same Device record.

### Google Drive for desktop (native macOS app, hardware-only signals)

The Drive desktop client runs outside the browser sandbox so it can read
hardware identifiers, but it doesn't collect security posture signals.

What it reports:
- `serialNumber`
- `hostname` (e.g. `My-MacBook-Pro.local`)
- `model` (precise)
- `osVersion`
- `ownerType`

What it does **not** report:
- `encryptionState` — Drive doesn't sample FileVault status

This is why a Mac with Drive for desktop installed but no EV will show up as
"hardware only" in the report — serial yes, encryption status no.

### Older / minimal registrations ("stale / minimal")

Records where `model` is the literal string `Mac OS` (not a precise model
identifier like `Mac16,5`) and most other fields are missing. These are
legacy registrations from older first-party clients that haven't re-synced.
They tend to have old `lastSyncTime` values and effectively zero diagnostic
value, but they remain in the inventory until pruned.

### Sign-in activity (separate report, Admin SDK Reports `login`)

Per-user sign-in events — when, from which IP, by which method
(`google_password`, `saml`, `oauth`, `reauth`, `unknown`), and whether
Google flagged the sign-in as suspicious — live in the Admin SDK Reports
`login` activity log. Surfaced by the sibling script
[`list_signins.py`](../list_signins.py).

Notable asymmetry vs. the device surface: **login events do not carry
browser user-agent**. IP and login method are the closest "where from"
identifiers available. If you need browser attribution for a specific Mac,
look at the EV-equipped Device records in `list_mac_devices.py` instead;
there is no per-sign-in browser data in Workspace audit logs.

### OAuth-app authorizations (separate report, not on Device records)

App-level authorizations — "what apps does user X have access tokens for" —
don't live on the Device resource at all. They live in the Admin SDK
Reports API `token` activity log, which records each OAuth grant or revoke
with both the client_id and a Google-curated friendly name like
"Google Drive for Desktop" or "Slack". That data is surfaced by the sibling
script [`list_app_authorizations.py`](../list_app_authorizations.py).

This is the cleanest channel for "what apps has this user authorized," and
unlike the device report it doesn't suffer from the system-browser-OAuth
ambiguity (the client_id belongs to the originating app, not whichever
browser hosted the consent screen).

### 3rd-party CAA partner signals (clientStates)

`devices.deviceUsers.clientStates` is a separate sub-resource where
Context-Aware Access **partners** (Crowdstrike, Jamf, etc.) write their own
signals against a device-user. Confirmed empirically: first-party Google
clients including Endpoint Verification do **not** write here. If your tenant
has no partner integration, this surface will always be empty, and that is
not a bug.

The `list_mac_devices.py --clients` flag queries this surface and is useful
only after a partner integration is in place.

## One Mac, multiple records

Each reporting channel creates its own Device record with its own `deviceId`.
A single physical Mac that has both Drive for desktop installed *and* a
managed Chrome signed in will appear as **two rows** in the report — one
hardware-only, one browser-only — and there is no clean join key (different
`deviceId`, possibly different `serialNumber` because one row has it and the
other doesn't).

The classifier in `list_mac_devices.py` labels each row by the signal mix
actually present in that record. To make the default report usable on a
real tenant without merging fictional fields, the script also prunes the
noisy long tail before display — see below.

## Why `list_mac_devices.py` filters by default

A real tenant accumulates many Device records per physical Mac: per user
session, per OS version, per first-party app that has reported in. On a
~90-user tenant we observed enough records to blow through Google's
**1500 read requests / minute** quota on `cloudidentity.googleapis.com`
when fanning out per-device. There's no server-side filter for
"recently active" or "has a serial," so we prune client-side after
`devices.list`.

Defaults:

1. Keep only records with a non-empty `serialNumber`.
2. Keep only records with `lastSyncTime` within the trailing
   `--last-sync-days` (default 30).
3. Dedupe by `serialNumber`, keeping the most recent record per serial.
   For multi-user Macs, the row's `USER` column is the union of every
   email Cloud Identity has attributed to any record sharing that serial.

This default reflects "the active managed fleet, one row per physical
Mac." For audits of dormant or signal-poor records (no serial, very old
sync, `stale / minimal` classifier), a future sibling script will surface
the inverse view — that's intentionally not this script's job, so its
defaults don't drift toward exhaustive enumeration.

## Signal-mix classifier (what shows up in the `SIGNALS` column)

| Label | Has `encryptionState` | Has `serialNumber` | Has `hostname` | Likely agent(s) |
|---|---|---|---|---|
| `browser + hardware` | ✓ | ✓ | varies | EV extension + native helper |
| `browser only` | ✓ | — | — | Signed-in managed Chrome (any first-party ext.) |
| `hardware only` | — | ✓ | ✓ | Drive for desktop (or similar native client) |
| `stale / minimal` | — | — | — | Old / minimal registration (`model == "Mac OS"`) |
| `unknown` | other combination | other combination | other combination | — |

## Sample output (default filter)

```
USER                              SIGNALS             SERIAL         MODEL        ASSET_TAG  ENCRYPTION  LAST_SYNC
--------------------------------  ------------------  -------------  -----------  ---------  ----------  ------------------------
alice@example.com                 browser + hardware  C02ZZZZZZZZZ1  MacBook Pro  -          ENCRYPTED   2026-05-29T18:19:07.448Z
bob@example.com, eve@example.com  hardware only       C02ZZZZZZZZZ2  Mac16,6      -          -           2026-05-29T16:02:30.005Z
```

Add `--include-browser` to pull each device's Chrome version (from the EV
signal block) as an extra column — at the cost of one `devices.get` call
per surviving device.

Reading this:

- One row per physical Mac (deduped by `serialNumber`).
- **alice's** Mac has the EV extension *and* native helper, so a single
  record carries both `serialNumber` and `encryptionState` and we know
  FileVault is on.
- **bob's** Mac is shared with **eve** (both have synced into it under
  managed identities); Drive for desktop is reporting the serial, but
  nothing on this machine is reporting encryption state. **Action item:**
  install EV on this machine so FileVault status surfaces.
- Records that fail the default filter — no serial (browser-only Chrome
  sessions like alice's older MacBookPro17,1, or carol/dave's machines
  that only have managed Chrome), or sync older than 30 days, or the
  classic `stale / minimal` model="Mac OS" placeholders — are dropped
  from this view. A future "outliers" report will surface them.

## Practical implications

- **To know FileVault status:** at minimum, the user needs a signed-in
  managed Chrome session with EV signal collection enabled in Admin. No
  native installs required.
- **To know serial number:** the user needs *either* Drive for desktop *or*
  the EV native helper installed.
- **To know both on the same record:** the user needs the EV extension *and*
  the EV native helper. This is the only single-record path to
  `encryptionState + serialNumber`.
- **Without a join key, deduplicating by physical machine is not reliable.**
  Treat each row as "what this particular reporting agent knows about a Mac
  associated with this user."
