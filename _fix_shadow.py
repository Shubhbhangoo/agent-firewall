"""Fix: 'for rule in rules' shadows the rule parameter."""

import io

path = "firewall/cli_v19.py"
source = io.open(path, encoding="utf-8").read()

# Remove all temporary debug lines.
debug_blocks = [
    """    detections = analyze_index(index)
    import sys as _sys
    print("DEBUG detections:", [(d.rule_id, d.agents) for d in detections], file=_sys.stderr)

    if rule is not None:""",
    """    records = []

    import sys as _sys
    print("DEBUG loop start:", len(detections), file=_sys.stderr)

    for detection in detections:
        try:
            print("DEBUG responding:", detection.rule_id, file=_sys.stderr)
            records.append(
                controller.respond(detection, actor="cli")
            )
        except BaseException as exc:
            print("DEBUG raised:", type(exc).__name__, str(exc)[:200], file=_sys.stderr)
            records.append(
                {
                    "rule_id": detection.rule_id,
                    "error": str(exc),
                }
            )""",
    """    import sys as _sys
    print("DEBUG records:", len(records), file=_sys.stderr)

    if as_json:""",
]

replaced = []
for block in debug_blocks:
    assert source.count(block) == 1, source.count(block)
    source = source.replace(block, "", 1)
    replaced.append(True)

# The BaseException debug variant replaced the plain except; restore the
# canonical form now that debug lines are gone.
old = """    for detection in detections:
        try:
            records.append(
                controller.respond(detection, actor="cli")
            )
        except BaseException as exc:
            records.append(
                {
                    "rule_id": detection.rule_id,
                    "error": str(exc),
                }
            )"""

new = """    for detection in detections:
        try:
            records.append(
                controller.respond(detection, actor="cli")
            )
        except Exception as exc:
            records.append(
                {
                    "rule_id": detection.rule_id,
                    "error": str(exc),
                }
            )"""

assert source.count(old) == 1, "except restore"
source = source.replace(old, new, 1)

# The real fix: rename the shadowing loop variable.
old = """    for rule in rules:
        controller.add_rule(rule)"""

new = """    for response_rule in rules:
        controller.add_rule(response_rule)"""

assert source.count(old) == 1, "shadow fix"
source = source.replace(old, new, 1)

io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("fixed rule shadowing; removed debug")
