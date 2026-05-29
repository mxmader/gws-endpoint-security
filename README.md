# endpoint-security

List every Mac device in our Google Workspace tenant along with its current
encryption status (FileVault) via the Cloud Identity Devices API.

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

Open <https://admin.google.com/ac/owl/domainwidedelegation>, click **Add new**,
and paste the Client ID and scope that `setup.sh` printed. Wait ~2 minutes for
propagation.

## Run the report

```bash
uv sync

export SA_EMAIL=endpoint-security-reader@<PROJECT>.iam.gserviceaccount.com
export WORKSPACE_ADMIN_EMAIL=admin@yourdomain.com   # any super-admin
uv run python list_mac_devices.py                   # add --json for raw output
```

## How auth works (no key file)

1. Your `gcloud` ADC token authenticates to the IAM Credentials API.
2. `google.auth.iam.Signer` asks `iamcredentials.signJwt` to sign a JWT *as*
   the service account, with `sub=<workspace admin>`.
3. The signed JWT is exchanged at `oauth2.googleapis.com/token` for a
   short-lived access token impersonating that admin — Google's standard
   domain-wide-delegation flow, just with the private key staying server-side.
