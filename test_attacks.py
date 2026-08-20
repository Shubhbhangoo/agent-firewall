from firewall.engine import Firewall

fw = Firewall()

attacks = [
    ("Negative payment", "payments.send", {"amount": -500}),
    ("Zero payment", "payments.send", {"amount": 0}),
    ("String amount", "payments.send", {"amount": "2000"}),
    ("Missing amount", "payments.send", {}),
    ("Unknown tool", "payments.fake", {"amount": 2000}),
    ("Huge payment", "payments.send", {"amount": 999999999}),
]

for name, tool, arguments in attacks:
    try:
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

    except Exception as e:
        print(
            f"{name}: CRASHED | "
            f"{type(e).__name__}: {e}"
        )