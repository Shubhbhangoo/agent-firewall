"""Temporary debug: patch command_respond to print detections."""

import io

path = "firewall/cli_v19.py"
source = io.open(path, encoding="utf-8").read()

old = """    detections = analyze_index(index)

    if rule is not None:"""

new = """    detections = analyze_index(index)
    import sys as _sys
    print("DEBUG detections:", [(d.rule_id, d.agents) for d in detections], file=_sys.stderr)

    if rule is not None:"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("debug added")
