import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
s = io.open("firewall/ui/static/control.js", encoding="utf-8").read()
print("lines:", len(s.splitlines()))
print(s[:900])
