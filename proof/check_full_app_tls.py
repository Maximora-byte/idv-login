"""Batch disposable loopback TLS fixtures through the source or frozen probe."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile

PREFIX = "IDV_TLS_PROOF_JSON="


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path,
                        default=Path(__file__).with_name("full_app_tls_probe.py"))
    parser.add_argument("--python", help="Interpreter for an unfrozen source probe")
    parser.add_argument("--public", action="store_true", help="Also test real public CA endpoints")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "tests"))
    from test_ssl_verification import local_tls_server

    probe = args.probe.resolve()
    body = b'{"lastModified":1,"ip":"203.0.113.7","data":[]}'
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="idv-tls-driver-")))
        cases = []
        for kind in ("trusted", "untrusted", "wrong_host", "expired"):
            url, ca_path = stack.enter_context(local_tls_server(kind, body=body))
            cases.append({"name": kind, "url": url, "ca_path": ca_path,
                          "success": kind == "trusted"})
            if kind == "trusted":
                # Separate default trust from deliberately supplied fixture trust.
                cases.append({"name": "default_bundle_rejects_private_ca", "url": url,
                              "success": False})
        if args.public:
            cases.extend([
                {"name": "public_cloud_default_bundle", "success": True,
                 "url": "https://raw.githubusercontent.com/KKeygen/idv-login/5359586d53f449bf5836aa8753d472863dfd500c/assets/cloudRes.json"},
                {"name": "public_ip_default_bundle", "success": True,
                 "url": "https://who.nie.netease.com/"},
            ])
        batch_path = directory / "batch.json"
        batch_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
        command = ([args.python] if args.python else []) + [str(probe), str(batch_path)]
        completed = subprocess.run(command, cwd=directory, capture_output=True,
                                   text=True, timeout=args.timeout)
        lines = [line[len(PREFIX):] for line in completed.stdout.splitlines()
                 if line.startswith(PREFIX)]
        if not lines:
            print(json.dumps({"passed": False, "returncode": completed.returncode,
                              "fatal": "Probe returned no structured result",
                              "stdout_tail": completed.stdout[-3000:],
                              "stderr_tail": completed.stderr[-3000:]}), flush=True)
            return 1
        result = json.loads(lines[-1])
        result["returncode"] = completed.returncode
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0 if completed.returncode == 0 and result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
