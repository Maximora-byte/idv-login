"""A standalone packaging smoke probe, never part of the production app."""
import json
import ssl
import sys

import requests
from ssl_utils import should_verify_ssl


assert should_verify_ssl() is True
roots = ssl.create_default_context(cafile=requests.certs.where()).get_ca_certs()
assert roots, "packaged certifi trust bundle must be readable and nonempty"
print(json.dumps({"policy": True, "packaged_roots": len(roots)}), flush=True)
if len(sys.argv) > 1:
    # Only this probe accepts an explicit temporary test CA bundle.
    requests.adapters.DEFAULT_CA_BUNDLE_PATH = sys.argv[2]
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(sys.argv[1], verify=should_verify_ssl(), timeout=5)
            response.raise_for_status()
        print("verified response", flush=True)
    except requests.exceptions.SSLError:
        print("rejected invalid certificate", flush=True)
        sys.exit(2)
