# endpoint-security

Reports for a Google Workspace tenant, run against a keyless service account
with domain-wide delegation:

- [`list_mac_devices.py`](./list_mac_devices.py) — active Macs (synced in
  the trailing 30 days, with a serial number, deduped by serial) with their
  encryption status (FileVault), signal mix, etc., from the Cloud Identity
  Devices API. Rows sorted with non-`ENCRYPTED` Macs first. Tune the window
  via `--last-sync-days N`; add the BROWSER column (Chrome version, one
  extra `devices.get` per device) via `--include-browser`.
- [`list_users_with_macs.py`](./list_users_with_macs.py) — every active
  Workspace user, correlated against the Mac survivor set. Rows sorted to
  surface users with **no Mac**, then users with at least one unencrypted
  Mac, then users with all-encrypted Macs. `--include-suspended`,
  `--only-no-mac` available.
- [`prune_devices.py`](./prune_devices.py) — **the only script that
  writes.** Dry-runs by default; lists devices that match the prune rules
  (Macs synced >30 days ago, or any device with no serial). `--execute`
  actually calls `devices.delete` (batched, with idempotent 404 handling
  and 429 retry).
- [`list_app_authorizations.py`](./list_app_authorizations.py) — every
  OAuth-authorized app per user (Drive desktop, Slack, Outlook, …) from the
  Admin SDK Reports `token` activity log.
- [`list_signins.py`](./list_signins.py) — per-user sign-in events with IP,
  login method, and suspicious-flag, from the Admin SDK Reports `login`
  activity log. (Note: browser user-agent is **not** on this surface.)

See [docs/google_device_data_sources.md](./docs/google_device_data_sources.md)
for what signals the device API actually exposes and how to interpret them.

## One-time setup

The bootstrap creates a service account that the listing script impersonates
via your local `gcloud` credentials — **no JSON key is ever written to disk**.

```bash
gcloud auth login                           # if not already logged in
gcloud auth application-default login       # needed for keyless impersonation

./setup.sh                                  # uses $GCP_PROJECT_ID; add --open to jump to Admin Console
```

To grant impersonation to a whole team rather than just yourself, pass a group
principal:

```bash
GRANTEE=group:endpoint-security@yourdomain.com ./setup.sh
```

`GRANTEE` accepts any IAM principal form (`user:`, `group:`, `serviceAccount:`,
`domain:`). Re-run with a different `GRANTEE` to add more — the binding is
additive. Default is `user:<your active gcloud account>`.

`setup.sh` will:

1. Enable `cloudidentity.googleapis.com` and `iamcredentials.googleapis.com`.
2. Create service account `endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com`.
3. Grant `GRANTEE` the `roles/iam.serviceAccountTokenCreator` role on the SA so
   the grantee can impersonate it.
4. Print the SA's OAuth Client ID + the exact URL/scope to paste into the
   Admin Console.

### Finish in the Admin Console (manual — no API for this)

This step requires a **super admin** because the DWD page itself is gated
to super admins by Google. It's a one-time configuration.

Open <https://admin.google.com/ac/owl/domainwidedelegation>, click **Add new**
(or edit the existing entry for the printed Client ID), and paste the Client
ID and the **comma-separated** scope list `setup.sh` printed:

```
https://www.googleapis.com/auth/cloud-identity.devices.readonly,
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/cloud-identity.devices,
https://www.googleapis.com/auth/admin.directory.user.readonly
```

What each scope powers:

- `cloud-identity.devices.readonly` — `list_mac_devices.py`,
  `list_users_with_macs.py` (Mac correlation).
- `admin.reports.audit.readonly` — `list_app_authorizations.py`,
  `list_signins.py`.
- `cloud-identity.devices` (write) — `prune_devices.py`.
- `admin.directory.user.readonly` — `list_users_with_macs.py` (user list).

Wait ~2 minutes for propagation.

## `WORKSPACE_ADMIN_EMAIL` — what privileges does it need?

The impersonated identity does **not** need to be a super admin. It needs
to be a Workspace user with an admin role that includes the right read
privileges for each script. Best practice is a dedicated "Security
Read-Only" custom admin role assigned to a service-style account.

| Script | Required admin-role privilege |
|---|---|
| `list_mac_devices.py` | Services → **Mobile Device Management** (Read) |
| `list_users_with_macs.py` | Services → **Mobile Device Management** (Read) + Admin API Privileges → **Users** (Read) |
| `prune_devices.py` | Services → **Mobile Device Management** (full — *not* the Read-only sub-privilege) |
| `list_app_authorizations.py` | Admin API Privileges → **Reports** (Read) |
| `list_signins.py` | Admin API Privileges → **Reports** (Read) |

A single role bundling all of these (full Mobile Device Management +
Users (Read) + Reports (Read)) covers every script. The only
*super-admin*-only thing in the whole flow is the one-time DWD entry above.

## Run the reports

```bash
uv sync

export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com
export WORKSPACE_ADMIN_EMAIL=security-reader@yourdomain.com  # see privilege table above

uv run python list_mac_devices.py                   # active Macs + encryption
uv run python list_users_with_macs.py               # users -> Macs correlation
uv run python list_app_authorizations.py --days 30  # OAuth app grants, last 30 days
uv run python list_signins.py --days 7              # sign-in events with IP + method
uv run python prune_devices.py                      # DRY RUN of prune candidates
uv run python prune_devices.py --execute            # actually delete
```

All five scripts accept `--format {plain,json,csv}` and `--output PATH`
for non-interactive consumption. See `--help` on each for the full flag set.

## How auth works (no key file)

1. Your `gcloud` ADC token authenticates to the IAM Credentials API.
2. `google.auth.iam.Signer` asks `iamcredentials.signJwt` to sign a JWT *as*
   the service account, with `sub=<workspace admin>`.
3. The signed JWT is exchanged at `oauth2.googleapis.com/token` for a
   short-lived access token impersonating that admin — Google's standard
   domain-wide-delegation flow, just with the private key staying server-side.
