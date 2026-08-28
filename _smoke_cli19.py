"""CLI end-to-end smoke for v1.9 network commands."""

import io
import json
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from firewall.recorder import FlightRecorder
from firewall.sdk import FirewallSDK

PY = sys.executable


def session(path, session_id, agent, cap_name, deny=False, secret=None, correlation=None, delegate_to=None):
    rec = FlightRecorder(session_id=session_id, agent=agent)
    if correlation:
        rec.set_meta("correlation_id", correlation)
    sdk = FirewallSDK(recorder=rec)
    sdk.generate_key("k")
    cap = sdk.issue(agent=agent, capability=cap_name, constraints={"amount_max": 100})
    sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
    if deny:
        for _ in range(5):
            sdk.authorize(cap, cap_name, {"amount": 99999})
    if secret:
        sdk.authorize(cap, cap_name, {"path": secret})
    if delegate_to:
        child = sdk.delegate(cap, sdk.active_key().private_key, delegatee=delegate_to).child
    rec.finalize()
    from firewall.artifact import write_artifact
    write_artifact(rec.artifact(), path)


session("_a1.afw", "sess-a", "agent-a", "payments.send", deny=True, secret="/etc/shadow", correlation="corr-1", delegate_to="ghost-agent")
session("_a2.afw", "sess-b", "agent-b", "files.read", correlation="corr-1")

def run(*args):
    r = subprocess.run([PY, "-m", "firewall.cli", *args], capture_output=True, text=True)
    print("$ firewall " + " ".join(args))
    if r.stdout:
        print(r.stdout.rstrip())
    if r.stderr:
        print("STDERR:", r.stderr.rstrip())
    print("exit:", r.returncode)
    return r

run("network", "init", "--out", "_net.json")
run("network", "ingest", "_a1.afw", "_a2.afw", "--state", "_net.json")
run("network", "correlate", "_net.json")
run("network", "graph", "_net.json", "--agent", "agent-a", "--reach")
run("network", "graph", "_net.json", "--who-can-reach", "/tmp/data")
run("detect", "_net.json")
run("attack-path", "_net.json", "--summary")

scenario = {
    "scenario_id": "s1",
    "kind": "compromised_agent",
    "title": "agent-a compromised",
    "agent": "agent-a",
    "added_capabilities": ["admin.bypass"],
}
json.dump(scenario, open("_scenario.json", "w"))

run("network", "simulate", "_net.json", "_scenario.json")

policy = {"rules": [
    {"rule_id": "credential_shaped_access", "min_severity": "high", "stage": "quarantine", "auto_approve": True},
]}
json.dump(policy, open("_policy.json", "w"))

run("respond", "_net.json", "--policy", "_policy.json", "--rule", "credential_shaped_access")

# verify v1.8 commands still work
run("verify", "_a1.afw")
