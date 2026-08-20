from firewall.engine import Firewall

fw = Firewall()

tests = [
    ("NaN", "payments.send", {"amount": float("nan")}),
    ("Infinity", "payments.send", {"amount": float("inf")}),
    ("Negative infinity", "payments.send", {"amount": float("-inf")}),
    ("Boolean", "payments.send", {"amount": True}),
    ("Null", "payments.send", {"amount": None}),
    ("List", "payments.send", {"amount": [500]}),
    ("Dict", "payments.send", {"amount": {"value": 500}}),
    ("Huge float", "payments.send", {"amount": 1e308}),
]

for name, tool, arguments in tests:
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