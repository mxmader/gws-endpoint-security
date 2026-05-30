#!/usr/bin/env bash
# One-time bootstrap for the Cloud Identity Devices reader service account.
# Idempotent: safe to re-run. No JSON key is ever created.
set -euo pipefail

SA_NAME="${SA_NAME:-endpoint-security-reader}"
SA_DISPLAY="Endpoint Security Reader"
SCOPES=(
  "https://www.googleapis.com/auth/cloud-identity.devices.readonly"
  "https://www.googleapis.com/auth/admin.reports.audit.readonly"
)
DWD_URL="https://admin.google.com/ac/owl/domainwidedelegation"

OPEN_ADMIN=0
for arg in "$@"; do
  case "$arg" in
    --open) OPEN_ADMIN=1 ;;
    -h|--help)
      cat <<EOF
Usage: GCP_PROJECT_ID=<id> [SA_NAME=<name>] [GRANTEE=<principal>] $0 [--open]

  --open    After printing the DWD instructions, open the Admin Console page.

Required env vars:
  GCP_PROJECT_ID   Existing GCP project that will host the service account.

Optional:
  SA_NAME       Service account local-part (default: endpoint-security-reader).
  GRANTEE       IAM principal to grant impersonation rights to. Must include
                the type prefix. Examples:
                  user:alice@example.com
                  group:endpoint-security@example.com
                  serviceAccount:ci@project.iam.gserviceaccount.com
                Default: user:<your active gcloud account>.
EOF
      exit 0
      ;;
  esac
done

: "${GCP_PROJECT_ID:?GCP_PROJECT_ID env var is required (existing GCP project ID)}"

command -v gcloud >/dev/null || { echo "gcloud not found in PATH" >&2; exit 1; }

# Preflight: ADC must be usable so the listing script can call iam.signJwt later.
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "Application Default Credentials are not configured." >&2
  echo "Run:  gcloud auth application-default login" >&2
  exit 1
fi

USER_EMAIL="$(gcloud config get-value account 2>/dev/null)"
[[ -n "$USER_EMAIL" ]] || { echo "No active gcloud account; run 'gcloud auth login'" >&2; exit 1; }

GRANTEE="${GRANTEE:-user:${USER_EMAIL}}"
case "$GRANTEE" in
  user:*|group:*|serviceAccount:*|domain:*) ;;
  *)
    echo "GRANTEE must start with a principal type prefix (user:, group:, serviceAccount:, domain:)." >&2
    echo "Got: $GRANTEE" >&2
    exit 1
    ;;
esac

SA_EMAIL="${SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

echo "==> Using project:       $GCP_PROJECT_ID"
echo "==> Service account:     $SA_EMAIL"
echo "==> Granting impersonation to: $GRANTEE"
echo

gcloud config set project "$GCP_PROJECT_ID" >/dev/null

echo "==> Enabling required APIs (cloudidentity, iamcredentials, admin)..."
gcloud services enable \
  cloudidentity.googleapis.com \
  iamcredentials.googleapis.com \
  admin.googleapis.com

echo "==> Creating service account (if missing)..."
if gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
  echo "    already exists, skipping create"
else
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="$SA_DISPLAY"
fi

echo "==> Granting roles/iam.serviceAccountTokenCreator to $GRANTEE on $SA_EMAIL..."
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --member="$GRANTEE" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --condition=None \
  >/dev/null

# Warn (don't delete) if user-managed keys exist from a prior key-based setup.
KEY_COUNT="$(gcloud iam service-accounts keys list \
  --iam-account="$SA_EMAIL" \
  --managed-by=user \
  --format='value(name)' | wc -l | tr -d ' ')"
if [[ "$KEY_COUNT" != "0" ]]; then
  echo
  echo "!! Warning: $SA_EMAIL has $KEY_COUNT user-managed key(s)." >&2
  echo "   This script uses keyless impersonation; existing keys are unused." >&2
  echo "   Consider deleting them with: gcloud iam service-accounts keys delete <KEY_ID> --iam-account=$SA_EMAIL" >&2
fi

OAUTH_CLIENT_ID="$(gcloud iam service-accounts describe "$SA_EMAIL" \
  --format='value(oauth2ClientId)')"

# Comma-separated string for the Admin Console DWD form, which accepts
# multiple scopes as one comma-delimited field.
SCOPES_CSV="$(IFS=, ; echo "${SCOPES[*]}")"

cat <<EOF

─── ACTION REQUIRED: complete domain-wide delegation ────────────────────────
Open: ${DWD_URL}
Click "Add new" (or edit the existing entry for this Client ID) and enter:
  Client ID:    ${OAUTH_CLIENT_ID}
  OAuth scopes: ${SCOPES_CSV}
─────────────────────────────────────────────────────────────────────────────

To run the reports once DWD is set up:

  export SA_EMAIL="${SA_EMAIL}"
  export WORKSPACE_ADMIN_EMAIL="<admin with the right read privileges; see README>"
  uv run python list_mac_devices.py
  uv run python list_app_authorizations.py --days 30
  uv run python list_signins.py --days 7

EOF

if [[ "$OPEN_ADMIN" == "1" ]]; then
  open "$DWD_URL" 2>/dev/null || true
fi
