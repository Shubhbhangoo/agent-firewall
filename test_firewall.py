from firewall.engine import Firewall

fw = Firewall()

tests = [
    ("READ", "github.read_file", {"path": "README.md"}),
    ("DELETE README", "github.delete_file", {"path": "README.md"}),
    ("DELETE PROD", "github.delete_file", {"path": "production.env"}),
    ("PAY $20", "payments.send", {"amount": 20}),
    ("PAY $500", "payments.send", {"amount": 500}),
    ("PAY $2000", "payments.send", {"amount": 2000}),
]

for name, tool, args in tests:
    result = fw.check("test-agent", tool, args)
    print(f"{name}: {result.action.upper()} | {result.reason}")