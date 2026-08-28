import io

path = "firewall/cli_v19.py"
source = io.open(path, encoding="utf-8").read()

old = """    records = []

    for detection in detections:
        try:
            records.append(
                controller.respond(detection, actor="cli")
            )"""

new = """    records = []

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
            )"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("debug3 added")
