import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_ssl_verification import local_tls_server


binary = str(Path("dist/tls-bundle-probe").resolve())
subprocess.run([binary], check=True, timeout=15)
for kind in ("trusted", "untrusted", "wrong_host", "expired"):
    with local_tls_server(certificate_kind=kind) as (url, ca_path):
        result = subprocess.run([binary, url, str(ca_path)], timeout=15)
        assert result.returncode == (0 if kind == "trusted" else 2), (kind, result.returncode)
    print("frozen TLS case passed:", kind, flush=True)
