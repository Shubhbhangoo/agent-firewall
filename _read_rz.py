import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
s = io.open("firewall/authorization.py", encoding="utf-8").read().splitlines()
for i in range(145, 205):
    print(i + 1, s[i])
