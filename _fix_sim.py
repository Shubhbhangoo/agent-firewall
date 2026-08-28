"""Fix network simulate parser (add state arg); debug respond."""

import io

# 1. Add the state positional to network simulate.
path = "firewall/cli.py"
source = io.open(path, encoding="utf-8").read()

old = """    network_simulate = network_sub.add_parser(
        "simulate",
        help=(
            "Simulate a security scenario (compromised agent, stolen "
            "capability, policy change, ...) in an isolated workspace."
        ),
    )
    network_simulate.add_argument(
        "scenario",
        help="Scenario JSON file.",
    )"""

new = """    network_simulate = network_sub.add_parser(
        "simulate",
        help=(
            "Simulate a security scenario (compromised agent, stolen "
            "capability, policy change, ...) in an isolated workspace."
        ),
    )
    network_simulate.add_argument(
        "state",
        help="Network state file.",
    )
    network_simulate.add_argument(
        "scenario",
        help="Scenario JSON file.",
    )"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("patched network simulate parser")

# 2. Debug respond directly.
import io as _io
import json as _json
import sys as _sys

_sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding="utf-8")

from firewall.network.state import build_index, load_state
from firewall.network.behavior import analyze_index

index, _ = build_index(load_state("_net.json"))
dets = analyze_index(index)
print("detections:", [(d.rule_id, d.agents) for d in dets])
filtered = [d for d in dets if d.rule_id == "credential_shaped_access"]
print("filtered:", len(filtered))

from firewall.containment import ContainmentController
from firewall.network import ResponseController, ResponseRule
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK

workspace = FirewallSDK(risk_context=RiskContext())
workspace.generate_key("k")
cc = ContainmentController(workspace, authorizer=lambda: True)
rc = ResponseController(cc)
rc.add_rule(ResponseRule(rule_id="credential_shaped_access", min_severity="high", stage="quarantine", auto_approve=True))
for d in filtered:
    rec = rc.respond(d, actor="cli")
    print("record:", rec.stage, rec.reason)
