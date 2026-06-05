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

### Endpoint Verification extension + native helper (chrome + hardware)

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

**IP ownership is not a Google field.** The `login` activity gives a bare
`ipAddress` plus a coarse geographic `networkInfo` block (`subdivisionCode` /
`regionCode`) — it carries **no ISP, ASN, or registrant**. The `OWNER` column
in `list_signins.py` is filled by a separate module,
[`ip_attribution.py`](../ip_attribution.py), which resolves each IP to its
**RDAP-registered network owner** (the org that holds the block at its RIR —
ARIN / RIPE / APNIC / LACNIC / AFRINIC) via the IANA RDAP bootstrap. Owners
are cached on disk keyed by the registered CIDR (`ip_attribution_cache.json`,
git-ignored — it holds real IPs); since registration data is very
slow-changing, the cache stays valid for months and only the first run on a
cold cache makes network calls. Enrichment is on by default;
`--no-ip-attribution` skips it. Private/reserved IPs render as
`private/reserved` and never hit the network.

### Authentication factors (`login_challenge_method`, same `login` log)

The *factor* a user actually authenticated with — passkey, FIDO2 security
key, password, TOTP/authenticator, Google prompt (push), backup code, SMS/voice
— is **not** on the `login_success` `login_type` field. It lives on the
`login_challenge` / `login_verification` events (which `list_signins.py`
filters out by default) in a parameter called **`login_challenge_method`**.
Surfaced by the sibling script
[`list_auth_factors.py`](../list_auth_factors.py) as a per-user rollup.

Quirks worth knowing:

- **It's multi-valued.** A single sign-in lists every challenge encountered,
  e.g. two bad password tries then a security key →
  `["password", "password", "security_key"]`. The shape returned by the
  discovery client is **not yet confirmed against this tenant** — the Reports
  API has been seen to encode multi-valued params as `multiValue` (plain
  strings), `multiStrValue`, or `multiValue` of `{"value": ...}` dicts. The
  `_param_multi` helper handles all three; **verify which one actually fires**
  before trusting the rollup (see that script's runbook).
- **Failed ≠ possession.** `login_challenge_status` is `"Challenge Passed."` /
  `"Challenge Failed."` (or empty). A *failed* security-key attempt must not
  make a user look like they use security keys, so only passed challenges
  contribute a factor.
- **Strength tiers** the script applies: passkey / `security_key` /
  `cross_device` / `device_prompt` = **strong** (phishing-resistant);
  `google_prompt` (push) / `google_authenticator` / `offline_otp` =
  **medium**; `backup_code` / `rescue_code` / `idv_*` (SMS, voice, email) =
  **weak**; `password` and `saml` = **none** (primary factor only). The
  per-user "weakest factor" ranks the weakest *second* factor — password is the
  primary and is excluded, so a user with no second factor reads as
  password-only (the worst posture).
- **SAML is opaque here.** For `saml` logins the real second factor lives at
  the external IdP and is invisible to Workspace, so it's flagged, not credited
  as strong.

The rollup is joined with each user's Directory **2-step-verification**
posture (`isEnrolledIn2Sv`, `isEnforcedIn2Sv`), producing four populations:
active enrolled users, in-directory users with **no sign-ins** in the window
(can't assess — sorted last), and identities that **signed in but aren't in the
directory** (ex-employees / external — 2SV shown as `?`). Rows sort
worst-posture-first, the same convention as the device reports.

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
Mac." Within the filtered set, rows are sorted so non-`ENCRYPTED` Macs
appear first — at-risk records are the top of the report and impossible
to miss.

Two companion scripts handle the inverse / user-centric views:

- **`prune_devices.py`** deletes the records this script filters out:
  any Mac with `lastSyncTime` older than 30 days (configurable), and any
  device of any type with no `serialNumber`. Dry-run by default;
  `--execute` opts in to actual `devices.delete` calls.
- **`list_users_with_macs.py`** pivots to a per-user view, surfacing
  Workspace users with **no Mac associated** (top of its sort) before
  users with at least one unencrypted Mac, then users with all-encrypted
  Macs.

The same device surface holds non-Mac platforms, handled by two sibling
listers documented in [Beyond Macs](#beyond-macs-mobile-and-everything-else)
below:

- **`list_mobile_devices.py`** — Android & iOS, sorted by integrity posture.
- **`list_other_devices.py`** — Windows / Linux / ChromeOS / Google Sync,
  sorted by disk-encryption risk like the Mac report.

## Signal-mix classifier (what shows up in the `SIGNALS` column)

| Label | Has `encryptionState` | Has `serialNumber` | Has `hostname` | Likely agent(s) |
|---|---|---|---|---|
| `chrome + hardware` | ✓ | ✓ | varies | EV extension + native helper |
| `chrome only` | ✓ | — | — | Signed-in managed Chrome (any first-party ext.) |
| `hardware only` | — | ✓ | ✓ | Drive for desktop (or similar native client) |
| `stale / minimal` | — | — | — | Old / minimal registration (`model == "Mac OS"`) |
| `unknown` | other combination | other combination | other combination | — |

## Sample output (default filter)

Sort puts non-`ENCRYPTED` rows first; encrypted rows follow.

```
USER                              SIGNALS             SERIAL         MODEL        ASSET_TAG  ENCRYPTION  LAST_SYNC
--------------------------------  ------------------  -------------  -----------  ---------  ----------  ------------------------
bob@example.com, eve@example.com  hardware only       C02ZZZZZZZZZ2  Mac16,6      -          -           2026-05-29T16:02:30.005Z
alice@example.com                 chrome + hardware   C02ZZZZZZZZZ1  MacBook Pro  -          ENCRYPTED   2026-05-29T18:19:07.448Z
```

Add `--include-browser` to pull each device's Chrome version (from the EV
signal block) as an extra column — at the cost of one `devices.get` call
per surviving device.

Reading this:

- One row per physical Mac (deduped by `serialNumber`).
- **bob's** Mac (top of the sort because it's not reporting `ENCRYPTED`)
  is shared with **eve** (both have synced into it under managed
  identities); Drive for desktop is reporting the serial, but nothing on
  this machine is reporting encryption state. **Action item:** install EV
  so FileVault status surfaces.
- **alice's** Mac has the EV extension *and* native helper, so a single
  record carries both `serialNumber` and `encryptionState` and we know
  FileVault is on.
- Records that fail the default filter — no serial (Chrome-only sessions
  like alice's older MacBookPro17,1, or carol/dave's machines that only
  have managed Chrome), or sync older than 30 days, or the classic
  `stale / minimal` model="Mac OS" placeholders — are dropped from this
  view. `prune_devices.py` is the script that physically
  deletes them; `list_users_with_macs.py --only-no-mac` is the place to
  see the users they left behind.

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

# Beyond Macs: mobile and everything else

The `deviceType` enum on a Device record takes one of: `ANDROID`, `IOS`,
`GOOGLE_SYNC`, `WINDOWS`, `MAC_OS`, `LINUX`, `CHROME_OS`, or the placeholder
`DEVICE_TYPE_UNSPECIFIED`. `list_mac_devices.py` keeps only `MAC_OS`; the two
sibling listers split the rest:

- `list_mobile_devices.py` → `ANDROID` + `IOS`
- `list_other_devices.py` → everything that is **not** `MAC_OS`, `ANDROID`,
  or `IOS` (i.e. `WINDOWS`, `LINUX`, `CHROME_OS`, `GOOGLE_SYNC`,
  `DEVICE_TYPE_UNSPECIFIED`).

Both reuse the same plumbing as the Mac script — the keyless DWD auth, the
active-sync-window filter (default 30 days), dedup to one row per physical
device (by `serialNumber` when present, else the device id), and the bulk
`deviceUsers.list` attribution pass. The difference is **which signals matter**,
and that changes the sort.

> Like the rest of this file, the field sets below are observations against the
> illustrative tenant, not a Google specification. Mobile reporting in
> particular varies sharply with the management tier the OU is on.

## Mobile (Android & iOS)

Where Mac risk is "is FileVault on," mobile risk is **device integrity** — is
the device rooted/jailbroken, sideloading, or otherwise tampered with.
Encryption is a near-constant on this surface (iOS is always hardware-encrypted;
Android has been file-based-encrypted by default since Android 10), so it earns
a column but does **not** drive the sort.

### How mobile devices register

- **Google endpoint management (basic vs. advanced).** Both Android and iOS
  reach Cloud Identity through Google's mobile management — the Google Device
  Policy app on Android, an APNs/MDM profile on iOS. **Basic** management
  yields a thin record (model, OS version, last sync, `managementState`).
  **Advanced** management unlocks the rich attribute set, and on Android
  specifically the `androidSpecificAttributes` block (Play Integrity /
  SafetyNet verdicts, verified boot, unknown-sources, harmful-apps).
- **Google Sync (ActiveSync).** Mail-only clients register as
  `deviceType: GOOGLE_SYNC`, **not** `IOS`/`ANDROID` — so an iPhone that only
  talks to Gmail over ActiveSync lands in `list_other_devices.py`, not the
  mobile report. (See the next section.)

### What the integrity signals are

`list_mobile_devices.py` collapses these into a `RISK_FLAGS` column and sorts
**compromised → other flags → clean**:

| Flag | Source field | Meaning |
|---|---|---|
| `compromised` | `compromisedState == COMPROMISED` | Rooted (Android) or jailbroken (iOS). Top of the sort. |
| `harmful-apps` | `androidSpecificAttributes.hasPotentiallyHarmfulApps` | Play Protect flagged installed app(s). |
| `cts-fail` | `androidSpecificAttributes.ctsProfileMatch == false` | Failed Play Integrity / SafetyNet CTS profile match. |
| `no-verified-boot` | `androidSpecificAttributes.verifiedBoot == false` | Boot chain not verified. |
| `verify-apps-off` | `androidSpecificAttributes.verifyAppsEnabled == false` | Play Protect scanning disabled. |
| `unknown-sources` | `androidSpecificAttributes.enabledUnknownSources` | Sideloading from outside Play allowed. |
| `dev-options` | `enabledDeveloperOptions` | Developer options enabled. |
| `usb-debug` | `enabledUsbDebugging` | ADB / USB debugging enabled. |

Android-only fields (`ctsProfileMatch`, `verifiedBoot`, `verifyAppsEnabled`,
`enabledUsbDebugging`, …) simply never appear on iOS records, so an iOS device
is only ever flagged via `compromised`. We treat a boolean as a problem only
when the API explicitly says so (`is False` / truthy) — a *missing* field is
never a flag.

### Field set by platform

- **Android, advanced management:** `serialNumber`, `model`, `brand`,
  `manufacturer`, `osVersion`, `releaseVersion`, `buildNumber`,
  `securityPatchTime`, `imei`/`meid`, `networkOperator`, `ownerType`,
  `managementState`, `compromisedState`, `encryptionState`, the developer/USB
  booleans, and the full `androidSpecificAttributes` block.
- **iOS, MDM-managed:** `serialNumber` (supervised/managed only — BYOD often
  omits it), `model`, `osVersion`, `imei`/`meid`, `ownerType`,
  `managementState`, `compromisedState`, `encryptionState`. No
  `androidSpecificAttributes`, no developer/USB booleans.
- **Either, basic management:** often just `model`, `osVersion`,
  `lastSyncTime`, `managementState`.

Because BYOD iOS commonly omits `serialNumber`, the mobile lister does **not**
require a serial by default (dedup falls back to the device id). Pass
`--require-serial` to drop serial-less records.

### Sample output (default sort)

Compromised first, then other risk flags, then clean.

```
USER               PLATFORM  MODEL       OS_VERSION  COMPROMISED   ENCRYPTION  RISK_FLAGS                  OWNER    MGMT      SERIAL         LAST_SYNC
-----------------  --------  ----------  ----------  ------------  ----------  --------------------------  -------  --------  -------------  ------------------------
bob@example.com    Android   Pixel 6     14          COMPROMISED   ENCRYPTED   compromised, unknown-sources COMPANY  APPROVED  C02ZZZZZZZZZ3  2026-06-03T09:11:02.000Z
carol@example.com  Android   Pixel 7     15          clean         ENCRYPTED   usb-debug, dev-options       BYOD     APPROVED  C02ZZZZZZZZZ4  2026-06-03T22:40:18.000Z
alice@example.com  iOS       iPhone15,2  18.5        clean         ENCRYPTED   -                            BYOD     APPROVED  -              2026-06-04T07:02:55.000Z
```

Reading this: **bob's** rooted Pixel that also allows sideloading is the top
action item; **carol's** Pixel is not compromised but has ADB and developer
options on (a posture concern on a BYOD device); **alice's** iPhone is clean and
reports no serial (expected for BYOD iOS) — it's keyed by device id.

## Everything else (Windows, Linux, ChromeOS, Google Sync)

`list_other_devices.py` is the catch-all. These are mostly **laptops and
desktops**, so disk encryption is the headline risk again and the script sorts
exactly like the Mac report: encryption-undetermined first, then
`NOT_ENCRYPTED`, then `ENCRYPTED` — with `deviceType` as the secondary grouping
so an unencrypted Windows box never hides behind a page of encrypted
Chromebooks.

### How these register

- **Windows / Linux** behave like Macs: **Endpoint Verification** (the Chrome
  extension, optionally plus the native helper) is the channel. The same
  signal-mix rules apply — the browser-only path reports `encryptionState`
  (BitLocker / dm-crypt-LUKS) but no serial; the native helper adds
  `serialNumber` and `hostname`. So a Windows row can be `chrome only`,
  `hardware only`, or `chrome + hardware` for the same reasons a Mac row can.
- **ChromeOS** (`deviceType: CHROME_OS`) is primarily managed through the Admin
  SDK `chromeosdevices` API, not Cloud Identity; what surfaces here tends to be
  a thin record. For the authoritative ChromeOS inventory, that other API is
  the right source.
- **Google Sync** (`deviceType: GOOGLE_SYNC`) is an ActiveSync mail client —
  minimal fields, no posture signals. Present so the catch-all is genuinely
  exhaustive; expect mostly empty columns.

### Field set

The encryption-bearing fields mirror the Mac surface (`encryptionState`,
`serialNumber`, `hostname`, `model`, `osVersion`, `manufacturer`,
`ownerType`, `managementState`). `compromisedState` and the Android block are
not populated for these types.

### Sample output (default sort)

Encryption-undetermined and `NOT_ENCRYPTED` rows first; encrypted rows follow.

```
USER             TYPE      MODEL            OS_VERSION  ENCRYPTION     HOSTNAME           OWNER    MGMT      SERIAL         LAST_SYNC
---------------  --------  ---------------  ----------  -------------  -----------------  -------  --------  -------------  ------------------------
dave@example.com Windows   Latitude 7440    11          NOT_ENCRYPTED  dave-win.local     COMPANY  APPROVED  C02ZZZZZZZZZ5  2026-06-02T14:05:00.000Z
eve@example.com  Linux     ThinkPad X1      -           -              -                  BYOD     APPROVED  -              2026-06-03T08:30:00.000Z
frank@example.com ChromeOS Chromebook       125         ENCRYPTED      -                  COMPANY  APPROVED  C02ZZZZZZZZZ6  2026-06-04T06:15:00.000Z
```

Reading this: **dave's** Windows laptop has BitLocker off (`NOT_ENCRYPTED`) —
the top action item; **eve's** Linux box reports only browser-level signals
(EV extension, no native helper), so encryption is undetermined and there's no
serial; **frank's** Chromebook is encrypted (ChromeOS storage is encrypted by
default) and clean.
