"""Patch version references: pyproject, workflows, and package metadata."""

import io
import re

# 1. pyproject.toml
path = "pyproject.toml"
source = io.open(path, encoding="utf-8").read()
old = 'version = "1.7.0"'
new = 'version = "1.8.0"'
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("pyproject.toml -> 1.8.0")

# 2. CI workflows: add v1.8 to branch lists.
for wf in (".github/workflows/security.yml", ".github/workflows/cli.yml"):
    path = wf
    source = io.open(path, encoding="utf-8").read()
    count = source.count("      - v1.7\n")
    assert count == 1, (wf, count)
    source = source.replace(
        "      - v1.7\n",
        "      - v1.7\n      - v1.8\n",
        1,
    )
    # Both push and pull_request blocks should gain v1.8.
    total = source.count("      - v1.8\n")
    assert total == 1, (wf, total)
    io.open(path, "w", encoding="utf-8", newline="\n").write(source)
    print(f"{wf} -> v1.8 added")
