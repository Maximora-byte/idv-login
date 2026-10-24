"""Disposable runner only: never run on a user's desktop."""
import copy
import os
import re
import subprocess
import uuid

from test_proxy_env import SavedState, load_proxy


assert os.environ.get("GITHUB_ACTIONS") == "true"


def networksetup(args):
    result = subprocess.run(["sudo", "-n", "/usr/sbin/networksetup", *args],
                            capture_output=True, text=True, timeout=15, check=True,
                            env=dict(os.environ, LC_ALL="C", LANG="C"))
    if "** Error" in result.stdout or "** Error" in result.stderr:
        raise OSError(result.stdout + result.stderr)
    return result.stdout.strip()


device = re.search(r"^Device: (\S+)$", networksetup(["-listallhardwareports"]), re.M).group(1)
service = "idv-proxy-test-" + uuid.uuid4().hex
networksetup(["-createnetworkservice", service, device])
try:
    networksetup(["-setnetworkserviceenabled", service, "off"])
    state = SavedState()
    module = load_proxy(state)
    module._networksetup = networksetup
    module._get_network_services = lambda: [service]
    initial = {p: module._read_darwin_proxy(service, p) for p in ("web", "secureweb")}
    print("Initial test service:", initial, flush=True)
    module._set_darwin(10717)
    module._unset_darwin()
    result = {p: module._read_darwin_proxy(service, p) for p in initial}
    print("Default empty/zero round trip:", result, flush=True)
    assert result == initial
    for server, port in (("", 0), ("", 8080), ("127.0.0.2", 0), ("127.0.0.2", 8080)):
        for protocol in initial:
            networksetup([f"-set{protocol}proxy", service, server, str(port), "off"])
            networksetup([f"-set{protocol}proxystate", service, "off"])
        before = {p: module._read_darwin_proxy(service, p) for p in initial}
        print("Configured edge case:", before, flush=True)
        module._set_darwin(10717)
        module._unset_darwin()
        after = {p: module._read_darwin_proxy(service, p) for p in initial}
        print("Restored edge case:", after, flush=True)
        assert before == after
    print("All native edge cases passed", flush=True)
finally:
    networksetup(["-removenetworkservice", service])
    print("Deleted disposable test service", flush=True)
