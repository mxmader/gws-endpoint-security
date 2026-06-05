#!/usr/bin/env python3

import os, json, sys
from list_mac_devices import build_credentials
from list_caa_events import fetch_caa_activity, SCOPES

creds = build_credentials(os.environ['SA_EMAIL'], os.environ['WORKSPACE_ADMIN_EMAIL'], SCOPES)
seen = set()
user = sys.argv[1]
for a in fetch_caa_activity(creds, '2026-05-01T00:00:00Z', user):
    ip, ni = a.get('ipAddress'), a.get('networkInfo')
    if ip and ip not in seen:
        seen.add(ip); print(ip, json.dumps(ni))
    if len(seen) >= 5: break
