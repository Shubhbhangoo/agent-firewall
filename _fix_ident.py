"""Fix the leftover temp-path line in IdentityRegistry._save."""

import io

PATH = "firewall/ident/registry.py"
source = io.open(PATH, encoding="utf-8").read()

old = """        directory = self._path.parent
        if str(directory) and str(directory) != ".":
            directory.mkdir(parents=True, exist_ok=True)

        fd, temp_path = os.path.join(
            str(directory) if str(directory) != "." else ".",
            ".identity-state.tmp",
        ), None

        import tempfile

        fd, temp_path = tempfile.mkstemp(
            prefix=".identity-state.",
            suffix=".tmp",
            dir=str(directory) if str(directory) != "." else ".",
        )"""

new = """        directory = self._path.parent
        if str(directory) and str(directory) != ".":
            directory.mkdir(parents=True, exist_ok=True)

        import tempfile

        fd, temp_path = tempfile.mkstemp(
            prefix=".identity-state.",
            suffix=".tmp",
            dir=str(directory) if str(directory) != "." else ".",
        )"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(source)
print("fixed _save temp path")
