import io

path = "firewall/cli_v19.py"
source = io.open(path, encoding="utf-8").read()

old = """    if as_json:
        _print_json(
            {
                "records": ["""

new = """    import sys as _sys
    print("DEBUG records:", len(records), file=_sys.stderr)

    if as_json:
        _print_json(
            {
                "records": ["""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("debug2 added")
