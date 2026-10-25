"""Validation-only frozen entrypoint; never call application startup or apply hotfixes."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile

PREFIX = "IDV_TLS_PROOF_JSON="


def trust_snapshot(requests, certifi):
    path = Path(certifi.where()).resolve()
    return {
        "certifi_path": str(path),
        "certifi_exists": path.is_file(),
        "certifi_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "adapter_ca_path": requests.adapters.DEFAULT_CA_BUNDLE_PATH,
        "default_context_roots": ssl.create_default_context().cert_store_stats(),
    }


@contextmanager
def controlled_ca(requests, ca_path):
    """Only fixture cases replace the adapter CA path; public cases use the bundle."""
    original = requests.adapters.DEFAULT_CA_BUNDLE_PATH
    if ca_path:
        requests.adapters.DEFAULT_CA_BUNDLE_PATH = ca_path
    try:
        yield
    finally:
        requests.adapters.DEFAULT_CA_BUNDLE_PATH = original


def run(batch):
    import requests
    import certifi

    before = trust_snapshot(requests, certifi)
    # Static import retains the real release entrypoint's dependency analysis.
    # argparse executes during import; main.main()/initialize() never execute.
    import main
    import app_state
    import cloudRes
    import gamecatalog
    import hotfixmgr
    import ssl_utils
    import envmgr
    import aiohttp
    import OpenSSL
    import mitmproxy.net.tls
    import PyQt6.QtNetwork
    import PyQt6.QtWebEngineCore

    after = trust_snapshot(requests, certifi)
    assert before == after, "Dependency imports changed default trust configuration"
    assert after["certifi_exists"], "Bundled CA data missing"
    assert Path(after["adapter_ca_path"]).resolve() == Path(after["certifi_path"])
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        assert Path(after["certifi_path"]).is_relative_to(Path(sys._MEIPASS).resolve())

    envmgr._cachePath = str(Path.cwd() / "config.json")
    envmgr.genv.set("FP_WORKDIR", str(Path.cwd()))
    envmgr.genv.set("SCRIPT_DIR", str(Path.cwd()))
    cloud = cloudRes.CloudRes([], str(Path.cwd()))
    assert cloud.session.trust_env is False
    assert cloud.dynamic_game_catalog.session.trust_env is False

    # Observe real adapter errors; retain the real transport and verification.
    observed = []
    original_send = requests.adapters.HTTPAdapter.send

    def observe_send(self, *args, **kwargs):
        assert kwargs.get("verify") is True, "Caller did not request verified TLS"
        try:
            return original_send(self, *args, **kwargs)
        except requests.RequestException as error:
            observed.append(type(error).__name__)
            raise

    requests.adapters.HTTPAdapter.send = observe_send
    rows = []
    try:
        for case in batch["cases"]:
            row = {"name": case["name"], "expected_success": case["success"]}
            with controlled_ca(requests, case.get("ca_path")):
                with requests.Session() as session:
                    session.trust_env = False
                    observed.clear()
                    try:
                        response = session.get(case["url"], verify=ssl_utils.should_verify_ssl(), timeout=15)
                        response.raise_for_status()
                        row["requests_success"] = True
                        row["requests_status"] = response.status_code
                    except requests.RequestException:
                        row["requests_success"] = False
                    row["requests_errors"] = list(observed)

                cloud.urls = [case["url"]]
                observed.clear()
                status, data = cloud.fetch_json_from_url()
                row["cloud_success"] = status == cloudRes._MODIFIED and isinstance(data, dict)
                row["cloud_errors"] = list(observed)

                observed.clear()
                ok, content, _error = hotfixmgr._download_text(case["url"], [])
                row["hotfix_success"] = ok and bool(content)
                row["hotfix_errors"] = list(observed)

            expected = case["success"]
            row["passed"] = all(row[key] is expected for key in
                                ("requests_success", "cloud_success", "hotfix_success"))
            if not expected:
                row["passed"] &= all(row[key] == ["SSLError"] for key in
                                     ("requests_errors", "cloud_errors", "hotfix_errors"))
            rows.append(row)
    finally:
        requests.adapters.HTTPAdapter.send = original_send
        cloud.session.close()
        cloud.dynamic_game_catalog.session.close()

    assert trust_snapshot(requests, certifi) == after, "Fixture CA override leaked"
    # No hotfix application function is invoked anywhere in this probe.
    assert not envmgr.genv.get("hotfix_records", {})
    assert not envmgr.genv.get("hotfix_pending_validate", [])
    return {
        "passed": all(row["passed"] for row in rows),
        "frozen": frozen,
        "platform": sys.platform,
        "requests_version": requests.__version__,
        "openssl_version": ssl.OPENSSL_VERSION,
        "trust_before": before,
        "trust_after": after,
        "actual_imports": ["main", "app_state", "cloudRes", "gamecatalog", "hotfixmgr",
                           "aiohttp", "OpenSSL", "mitmproxy.net.tls",
                           "PyQt6.QtNetwork", "PyQt6.QtWebEngineCore"],
        "boundary": "No main()/initialize(), QApplication, hotfix apply, or system mutation",
        "cases": rows,
    }


if __name__ == "__main__":
    batch_path = Path(sys.argv[1]).resolve()
    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    sys.argv = ["full-app-tls-proof"]
    if not getattr(sys, "frozen", False):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    original_cwd = Path.cwd()
    try:
        with tempfile.TemporaryDirectory(prefix="idv-full-tls-proof-") as temporary:
            os.chdir(temporary)
            try:
                result = run(batch)
            finally:
                os.chdir(original_cwd)
                if "loguru" in sys.modules:
                    sys.modules["loguru"].logger.remove()
    except Exception as error:
        os.chdir(original_cwd)
        result = {"passed": False, "fatal_type": type(error).__name__, "fatal": str(error)}
    print(PREFIX + json.dumps(result, sort_keys=True), flush=True)
    raise SystemExit(0 if result["passed"] else 1)
