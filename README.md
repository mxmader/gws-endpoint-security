# endpoint-security

Reports for a Google Workspace tenant, run against a keyless service account
with domain-wide delegation:

- [`list_mac_devices.py`](./list_mac_devices.py) — every Mac with its
  encryption status (FileVault), reporting browser, signal mix, etc., from
  the Cloud Identity Devices API.
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

Open <https://admin.google.com/ac/owl/domainwidedelegation>, click **Add new**
(or edit the existing entry for the printed Client ID), and paste the Client
ID and the **comma-separated** scope list `setup.sh` printed:

```
https://www.googleapis.com/auth/cloud-identity.devices.readonly,
https://www.googleapis.com/auth/admin.reports.audit.readonly
```

The first scope powers `list_mac_devices.py`; the second powers
`list_app_authorizations.py`. Wait ~2 minutes for propagation.

## Run the reports

```bash
uv sync

export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com
export WORKSPACE_ADMIN_EMAIL=admin@yourdomain.com   # any super-admin

uv run python list_mac_devices.py                   # all Macs + encryption status
uv run python list_app_authorizations.py --days 30  # OAuth app grants, last 30 days
uv run python list_signins.py --days 7              # sign-in events with IP + method
```

All three scripts accept `--json` for raw output. See `--help` on each for
other flags (`--clients`, `--view`, `--user`, `--show-revoked`,
`--failures-only`, …).

## How auth works (no key file)

1. Your `gcloud` ADC token authenticates to the IAM Credentials API.
2. `google.auth.iam.Signer` asks `iamcredentials.signJwt` to sign a JWT *as*
   the service account, with `sub=<workspace admin>`.
3. The signed JWT is exchanged at `oauth2.googleapis.com/token` for a
   short-lived access token impersonating that admin — Google's standard
   domain-wide-delegation flow, just with the private key staying server-side.
