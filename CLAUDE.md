# Repo notes

## Sanitization

This repo is shared publicly. Never use Workspace-specific metadata — real
user emails, domain names, employee names, hostnames, serial numbers, OAuth
client IDs, IP addresses, GCP project IDs — in any of:

- Script argument / input examples in docs, README, or `--help` text.
- Output examples in docs or README.
- Default values for script variables, constants, or CLI flag defaults.

Use placeholders: `alice@example.com`, `yourdomain.com`, `C02ZZZZZZZZZ1`,
`<PROJECT>`, etc.

## Architecture quick-ref

- **Shared helpers live in `list_mac_devices.py`:** `build_credentials`,
  `_run_batch`, `_execute`, `_format_plain`, `write_formatted`. Other scripts
  import from there. Add new shared helpers here when more than one script
  needs them.
- **Auth: keyless DWD.** Local gcloud ADC + `iam.Signer` →
  `iamcredentials.signJwt` → token exchange. No JSON key on disk.
- All scripts accept `--format {plain,json,csv}` + `--output PATH`,
  dispatched via `write_formatted`.
- API quirks and signal-source observations: `docs/google_device_data_sources.md`.
