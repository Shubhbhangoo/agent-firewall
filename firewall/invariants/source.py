"""Source-level (AST) checks for the structural v2.2 invariants.

Four of the fifteen invariants are properties of the *code*, not of any
particular run: which modules may construct an authorization verdict,
which functions may return an allow, which modules may reach into the
authorization data plane, and whether a security vocabulary has been
duplicated. Those are checked here by parsing every module under
``firewall/`` with :mod:`ast`.

Static checking is used for these deliberately. A runtime probe can only
report on the paths it happens to exercise; "no module outside
``firewall/sdk.py`` constructs an ``AuthorizationResult``" is a claim
about all paths, and only reading the source can support it.

A file that will not parse is reported as a finding rather than skipped.
Skipping it would let a syntax error hide a violation.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, Optional


def package_root() -> Optional[Path]:
    """Directory of the installed/checked-out ``firewall`` package.

    Resolved from this module's own location rather than the working
    directory, so the checks read the same source tree that is imported.
    A stale copy elsewhere on ``sys.path`` would otherwise be checked
    while a different one runs.
    """

    here = Path(__file__).resolve()

    for parent in here.parents:
        if parent.name == "firewall":
            return parent

    return None


def source_modules(
    root: Optional[Path] = None,
) -> list[Path]:
    """Every ``.py`` file in the package, excluding caches, sorted."""

    base = root if root is not None else package_root()

    if base is None:
        return []

    return sorted(
        path
        for path in base.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def relative_name(path: Path, root: Path) -> str:
    """``firewall/sdk.py``-style label, POSIX separators on every OS."""

    try:
        return "firewall/" + path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


class ParseFailure(Exception):
    """A module under ``firewall/`` could not be parsed."""


def parse_module(path: Path) -> ast.Module:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ParseFailure(str(error)) from error

    try:
        return ast.parse(text, filename=str(path))
    except SyntaxError as error:
        raise ParseFailure(
            f"line {error.lineno}: {error.msg}"
        ) from error


def called_name(node: ast.Call) -> Optional[str]:
    """Rightmost name of a call target.

    ``AuthorizationResult(...)`` and ``authorization.AuthorizationResult(...)``
    both yield ``AuthorizationResult``. Matching on the attribute tail is
    what makes the check resistant to import aliasing of the module,
    though not of the name itself -- see
    :func:`aliased_import_names`.
    """

    func = node.func

    if isinstance(func, ast.Name):
        return func.id

    if isinstance(func, ast.Attribute):
        return func.attr

    return None


def aliased_import_names(
    tree: ast.Module,
    target: str,
) -> set[str]:
    """Local names that refer to ``target`` in this module.

    ``from firewall.authorization import AuthorizationResult as R`` would
    otherwise defeat a name-based search. The returned set always
    includes ``target`` itself.
    """

    names = {target}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == target and alias.asname:
                    names.add(alias.asname)

    return names


def walk_calls(
    tree: ast.AST,
) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def function_defs(
    tree: ast.AST,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            yield node


def is_literal_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_literal_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def allowed_argument(
    node: ast.Call,
) -> Optional[ast.AST]:
    """The ``allowed`` argument of an ``AuthorizationResult(...)`` call.

    ``AuthorizationResult`` takes ``allowed`` first, so both the
    positional and keyword forms are resolved here. ``None`` means the
    call passes it some way this function does not model (``**kwargs``),
    which callers must treat as *not* provably a denial.
    """

    for keyword in node.keywords:
        if keyword.arg == "allowed":
            return keyword.value

    if node.args:
        return node.args[0]

    return None


def attribute_accesses(
    tree: ast.AST,
    names: frozenset[str],
) -> Iterator[ast.Attribute]:
    """Every ``<expr>.<name>`` access where ``name`` is in ``names``."""

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in names:
            yield node


def receiver_label(node: ast.AST) -> Optional[str]:
    """Rightmost identifier of a receiver expression.

    ``sdk`` -> ``sdk``, ``self._sdk`` -> ``_sdk``, ``ws.sdk`` -> ``sdk``,
    ``workspace`` -> ``workspace``. Anything more complex (a call, a
    subscript) returns ``None``.
    """

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        return node.attr

    return None


def is_sdk_receiver(node: ast.AST) -> bool:
    """Whether a receiver expression plausibly denotes a ``FirewallSDK``.

    Name-based, because a static check has no types to consult. The
    consequence is worth stating: a module that binds an SDK to a name
    with no ``sdk``/``workspace`` in it would not be inspected. That is
    the accepted limit of the check -- the alternative, matching on
    attribute name alone, reports every subsystem's *own* injected
    registry as a violation and so has no signal at all.
    """

    label = receiver_label(node)

    if label is None:
        return False

    lowered = label.lower()

    return "sdk" in lowered or "workspace" in lowered


#: Builtins that reach an attribute through a string name.
_REFLECTIVE_BUILTINS = frozenset(
    {"getattr", "hasattr", "setattr", "delattr"}
)


def reflective_accesses(
    tree: ast.AST,
    names: frozenset[str],
) -> Iterator[tuple[ast.Call, str]]:
    """``getattr(x, "_name")``-style reaches for a name in ``names``.

    Yields ``(call, attribute_name)``. Without this,
    ``getattr(sdk, "_capability_registry", {})`` is invisible to
    :func:`attribute_accesses`.
    """

    for node in walk_calls(tree):
        if called_name(node) not in _REFLECTIVE_BUILTINS:
            continue

        if len(node.args) < 2:
            continue

        target = node.args[1]

        if not isinstance(target, ast.Constant):
            continue

        if target.value in names:
            yield node, target.value



def string_constants(
    tree: ast.AST,
) -> Iterator[tuple[int, str]]:
    """``(lineno, value)`` for every string literal in the tree.

    Needed because ``getattr(sdk, "_capability_registry")`` hides a
    private access from :func:`attribute_accesses`.
    """

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(
            node.value,
            str,
        ):
            yield node.lineno, node.value


def enum_class_defs(
    tree: ast.AST,
) -> Iterator[ast.ClassDef]:
    """Class definitions that look like an ``Enum`` subclass."""

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        bases = {
            base.id
            for base in node.bases
            if isinstance(base, ast.Name)
        } | {
            base.attr
            for base in node.bases
            if isinstance(base, ast.Attribute)
        }

        if bases & {"Enum", "StrEnum", "IntEnum"}:
            yield node


def enum_member_values(
    node: ast.ClassDef,
) -> frozenset[str]:
    """String values assigned to simple members of an enum class body."""

    values: set[str] = set()

    for statement in node.body:
        if not isinstance(statement, ast.Assign):
            continue

        if not isinstance(statement.value, ast.Constant):
            continue

        if not isinstance(statement.value.value, str):
            continue

        for target in statement.targets:
            if isinstance(target, ast.Name):
                values.add(statement.value.value)

    return frozenset(values)
