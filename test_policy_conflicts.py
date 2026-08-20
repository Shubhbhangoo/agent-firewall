from firewall.engine import Firewall

fw = Firewall()

tests = [
    ("Normal payment", "payments.send", {"amount": 50}),
    ("Approval payment", "payments.send", {"amount": 500}),
    ("Denied payment", "payments.send", {"amount": 2000}),
    ("Protected file", "github.delete_file", {"path": "production.env"}),
    ("Allowed file", "github.delete_file", {"path": "README.md"}),
]

for name, tool, arguments in tests:
    result = fw.check(
        "attacker-agent",
        tool,
        arguments,
    )

    print(
        f"{name}: "
        f"{result.action.upper()} | "
        f"{result.reason}"
    )