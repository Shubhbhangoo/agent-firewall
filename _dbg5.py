import io, sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import firewall.cli_v19 as v19

code = v19.command_respond(
    "_net2.json",
    rule="credential_shaped_access",
    severity=None,
    policy_path="_policy2.json",
    as_json=False,
)
print("exit:", code)
