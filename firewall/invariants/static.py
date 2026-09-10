"""The four structural invariants, checked against the source tree.

AUTHORIZATION_UNIQUENESS, MODEL_NON_AUTHORITY, CONTROL_PLANE_INTEGRITY
and the vocabulary half of PROVENANCE_INTEGRITY are claims about every
code path, so they are checked by reading the code rather than by
probing a run.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Optional

from firewall.invariants import source
from firewall.invariants.model import (
    InvariantResult,
    holds,
    unverifiable,
    violated,
)


#: Only these modules may construct an ``AuthorizationResult``.
#:
#: ``firewall/authorization.py`` owns the verdict type and the constraint
#: evaluation that produces it; ``firewall/sdk.py`` owns the gate chain
#: that decides which verdict is returned. Every other subsystem --
#: risk, intel, twin, telemetry, monitoring, UI, adapters -- may produce
#: evidence and recommendations, and must route an actual decision
#: through ``FirewallSDK.authorize``.
AUTHORIZATION_RESULT_OWNERS = frozenset(
    {
        "firewall/authorization.py",
        "firewall/sdk.py",
    }
)

#: The functions that build a verdict, and the parameter that carries the
#: answer.
#:
#: ``AuthorizationResult`` is the dataclass; ``_result`` is the private
#: factory in ``firewall/authorization.py`` that every branch of the
#: canonical ``authorize`` routes through. Searching only for the
#: dataclass misses the factory, and the factory is where allows are
#: actually minted, so both are treated as construction sites.
VERDICT_FACTORIES: tuple[str, ...] = (
    "AuthorizationResult",
    "_result",
)

#: The functions permitted to pass a non-literal ``allowed``, and why.
#:
#: Every other verdict construction in an owner module must pass a
#: literal ``False``. This list is the closed set of places where a
#: value that *might* be ``True`` can reach a verdict, so a new entry is
#: a deliberate, reviewed act rather than a diff nobody looked at twice.
#:
#: Keyed ``(module, enclosing function)``. Matching on the enclosing
#: function -- not merely the module -- is what gives the census teeth:
#: a module-level census waves through every site in ``sdk.py``, which
#: is 46 of the 50 in the package.
VERDICT_FORWARDING_SITES: dict[tuple[str, str], str] = {
    ("firewall/authorization.py", "_result"): (
        "forwards its own allowed parameter into the dataclass; its "
        "call sites are what this check constrains"
    ),
    ("firewall/authorization.py", "authorize"): (
        "the canonical boundary -- the one place in the package where "
        "an allow originates"
    ),
    ("firewall/sdk.py", "_trace_result"): (
        "projects an existing verdict's allowed onto a traced copy; "
        "cannot answer differently than the verdict it copies"
    ),
    ("firewall/sdk.py", "_withhold_on_degraded_dependencies"): (
        "downgrades an allow when a security dependency is degraded; "
        "returns denials untouched and can only move allow -> deny"
    ),
}

#: The single site where an allow originates.
#:
#: ``firewall/authorization.py`` line 484 at the time of writing:
#: ``_result(capability, action, True, "authorized")``, reached only
#: after every check in the canonical ``authorize`` has passed. Pinned by
#: ``(module, function)`` rather than by line so that moving the code
#: does not fail the invariant, while adding a *second* such site does.
ALLOW_ORIGIN: tuple[str, str] = (
    "firewall/authorization.py",
    "authorize",
)

#: The one gate permitted to return an allow.
#:
#: Every other gate in ``FirewallSDK._authorization_gate_phases`` may
#: only refuse or abstain, which is what makes the chain fail-closed:
#: adding a gate can never widen authority, only narrow it.
TERMINAL_ALLOW_FUNCTION = "_gate_transaction"

#: Mutable control-plane state that must not be reached from outside
#: ``firewall/sdk.py``.
#:
#: These are the containers the authorization path itself reads: the
#: capability registry resolves lineage fingerprints during the ancestor
#: walk, and the identity/task/posture state feeds continuous
#: authorization. A subsystem holding a reference to the live container
#: can replace a parent capability, delete an ancestor, or mark an
#: identity valid -- none of which is an authorization call, and all of
#: which change what ``authorize`` decides.
CONTROL_PLANE_STATE = frozenset(
    {
        "_capability_registry",
        "_identity_registry",
        "_task_registry",
        "_posture_engine",
    }
)

#: Private authorization *logic* that shared readers legitimately reuse.
#:
#: Reaching for a private method is coupling, not escalation: the
#: read-only UI projection and the case recorder must resolve a
#: delegation chain the same way the gate chain does, and forcing them to
#: reimplement it would create exactly the second, divergent
#: representation that would be a real security problem. These are
#: reported in ``details`` so the coupling stays visible, and do not fail
#: the invariant.
CONTROL_PLANE_SHARED_LOGIC = frozenset(
    {
        "_authorization_gate_phases",
        "_resolve_delegation_authority",
    }
)

#: The canonical provenance vocabulary.
#:
#: ``firewall.network.model.Provenance`` is the one definition;
#: ``firewall.platform`` re-exports it. A second enum with these members
#: compares equal member-by-member when both subclass ``str``, so a
#: duplicate does not break anything visibly -- it just means two
#: subsystems can drift apart while appearing to agree.
PROVENANCE_VALUES = frozenset(
    {
        "observed",
        "derived",
        "inferred",
        "simulated",
        "unknown",
    }
)

PROVENANCE_OWNERS = frozenset(
    {
        "firewall/network/model.py",
    }
)


def _collect(
    name: str,
) -> tuple[Optional[Path], list[Path], list[str]]:
    """Locate the package and parse-check its modules.

    Returns ``(root, modules, parse_failures)``. Parse failures are
    findings, not skips.
    """

    root = source.package_root()

    if root is None:
        return None, [], []

    modules = source.source_modules(root)
    failures: list[str] = []

    return root, modules, failures


def _verdict_factories(
    tree: ast.Module,
) -> dict[str, tuple[str, int]]:
    """Local names that build a verdict, mapped to their answer argument.

    The dataclass carries ``allowed`` first. ``_result`` carries it
    wherever its own signature puts it, which is read from the
    definition in this module rather than assumed, so that reordering
    the factory's parameters cannot leave this check inspecting the
    wrong argument and reporting a pass.
    """

    factories: dict[str, tuple[str, int]] = {}

    for local in source.aliased_import_names(
        tree,
        "AuthorizationResult",
    ):
        factories[local] = ("allowed", 0)

    for function in source.function_defs(tree):
        if function.name != "_result":
            continue

        index = source.parameter_index(function, "allowed")

        if index is not None:
            factories["_result"] = ("allowed", index)

    return factories


def check_authorization_uniqueness() -> InvariantResult:
    """A verdict is built only where the boundary builds one.

    Three claims, each narrower than the last:

    1. Only ``AUTHORIZATION_RESULT_OWNERS`` construct a verdict at all.
    2. Within those modules, every construction passes a literal
       ``False`` unless its enclosing function is a declared entry in
       ``VERDICT_FORWARDING_SITES``.
    3. Exactly one site in the package passes a literal ``True``, and it
       is ``ALLOW_ORIGIN``.

    Claim 1 alone was the v2.4 formulation, and it has a
    module-shaped hole: ``firewall/sdk.py`` is an owner, so all 46 of
    its construction sites were waved through, and a non-gate helper
    returning ``AuthorizationResult(allowed=True, ...)`` kept this
    invariant and ``MODEL_NON_AUTHORITY`` green -- the latter inspects
    only functions named ``_gate_*``. Claims 2 and 3 close that hole by
    moving the census from module granularity to function granularity.

    Formulated as "must pass a literal ``False``" rather than "must not
    pass a literal ``True``", because allow verdicts flow through
    variables: requiring the denial to be visible is the only
    formulation with teeth, and it makes every value that *might* be
    ``True`` land in the declared list.
    """

    name = "AUTHORIZATION_UNIQUENESS"
    root, modules, _ = _collect(name)

    if root is None or not modules:
        return unverifiable(
            name,
            "could not locate the firewall package source tree",
        )

    findings: list[str] = []
    parse_failures: list[str] = []
    owners_seen: set[str] = set()
    forwarding_seen: set[tuple[str, str]] = set()
    allow_origins: list[str] = []
    denials = 0

    for path in modules:
        label = source.relative_name(path, root)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            parse_failures.append(f"{label}: {error}")
            continue

        factories = _verdict_factories(tree)
        enclosing = source.call_owners(tree)

        for call in source.walk_calls(tree):
            called = source.called_name(call)

            if called not in factories:
                continue

            if label not in AUTHORIZATION_RESULT_OWNERS:
                findings.append(
                    f"{label}:{call.lineno} constructs an "
                    "AuthorizationResult outside the authorization "
                    "boundary"
                )
                continue

            owners_seen.add(label)
            function = enclosing.get(id(call)) or "<module>"
            parameter, index = factories[called]
            site = f"{label}:{call.lineno} in {function}"

            argument = source.argument_by_name_or_position(
                call,
                parameter,
                index,
            )

            if argument is None:
                findings.append(
                    f"{site} builds a verdict without a resolvable "
                    f"{parameter} argument, so it is not provably a "
                    "denial"
                )
                continue

            if source.is_literal_false(argument):
                denials += 1
                continue

            key = (label, function)

            if key not in VERDICT_FORWARDING_SITES:
                findings.append(
                    f"{site} passes an {parameter} argument that is "
                    "not a literal False from a function that is not "
                    "a declared verdict-forwarding site"
                )
                continue

            forwarding_seen.add(key)

            if source.is_literal_true(argument):
                allow_origins.append(site)

    if findings:
        return violated(
            name,
            "a verdict is built somewhere the boundary does not build "
            "one",
            findings=tuple(findings),
            parse_failures=parse_failures,
        )

    if parse_failures:
        return unverifiable(
            name,
            "some modules could not be parsed, so the census is "
            "incomplete",
            findings=tuple(parse_failures),
        )

    if not owners_seen:
        return unverifiable(
            name,
            "no AuthorizationResult construction was found anywhere, "
            "which means the check is not reaching the source it "
            "believes it is reading",
        )

    origin = f"{ALLOW_ORIGIN[0]} in {ALLOW_ORIGIN[1]}"
    declared = [
        site
        for site in allow_origins
        if site.rsplit(":", 1)[0] == ALLOW_ORIGIN[0]
        and site.endswith(f" in {ALLOW_ORIGIN[1]}")
    ]

    if len(allow_origins) != 1 or len(declared) != 1:
        return violated(
            name,
            f"an allow must originate in exactly one place ({origin})",
            findings=tuple(allow_origins)
            or ("no site in the package passes a literal True",),
        )

    return holds(
        name,
        "a verdict is built only in "
        f"{sorted(owners_seen)}, an allow originates only at "
        f"{allow_origins[0]}",
        modules_scanned=len(modules),
        denial_sites=denials,
        forwarding_sites=len(forwarding_seen),
    )


def check_model_non_authority() -> InvariantResult:
    """Only the terminal gate may return an allow.

    Every gate in the chain either refuses (returns a denial) or abstains
    (returns ``None``); only ``_gate_transaction`` may produce an allow.
    That is what makes the chain monotonically restrictive: a new gate --
    a risk score, a behavioural signal, a model verdict -- can subtract
    authority but has no expressible way to add it.

    Checked structurally: inside every ``_gate_*`` function other than
    the terminal one, an ``AuthorizationResult`` construction must pass a
    literal ``False``. A variable would be enough to smuggle an allow
    through, so a non-literal is a finding rather than a pass.
    """

    name = "MODEL_NON_AUTHORITY"
    root = source.package_root()

    if root is None:
        return unverifiable(
            name,
            "could not locate the firewall package source tree",
        )

    path = root / "sdk.py"

    if not path.is_file():
        return unverifiable(
            name,
            "firewall/sdk.py is missing, so the gate chain cannot be "
            "inspected",
        )

    try:
        tree = source.parse_module(path)
    except source.ParseFailure as error:
        return unverifiable(
            name,
            f"firewall/sdk.py could not be parsed: {error}",
        )

    aliases = source.aliased_import_names(
        tree,
        "AuthorizationResult",
    )

    findings: list[str] = []
    gates_seen: list[str] = []

    for function in source.function_defs(tree):
        if not function.name.startswith("_gate_"):
            continue

        gates_seen.append(function.name)

        if function.name == TERMINAL_ALLOW_FUNCTION:
            continue

        for call in source.walk_calls(function):
            if source.called_name(call) not in aliases:
                continue

            argument = source.allowed_argument(call)

            if argument is None:
                findings.append(
                    f"firewall/sdk.py:{call.lineno} in {function.name} "
                    "constructs an AuthorizationResult without a "
                    "resolvable allowed argument"
                )
                continue

            if not source.is_literal_false(argument):
                findings.append(
                    f"firewall/sdk.py:{call.lineno} in {function.name} "
                    "constructs an AuthorizationResult whose allowed "
                    "argument is not a literal False"
                )

    if findings:
        return violated(
            name,
            "a non-terminal gate can produce something other than a "
            "denial",
            findings=tuple(findings),
        )

    if TERMINAL_ALLOW_FUNCTION not in gates_seen:
        return unverifiable(
            name,
            f"{TERMINAL_ALLOW_FUNCTION} was not found in "
            "firewall/sdk.py, so the gate chain being checked is not "
            "the one that runs",
        )

    return holds(
        name,
        f"{len(gates_seen) - 1} non-terminal gates can only deny or "
        "abstain",
        gates=sorted(gates_seen),
    )


def check_control_plane_integrity() -> InvariantResult:
    """Control-plane state is reachable only through the SDK's own API.

    The capability registry is read by the authorization path itself: the
    ancestor walk resolves each lineage fingerprint through it, so an
    entry that is replaced decides which parent constraints a delegated
    capability is held to. A subsystem holding the live ``dict`` can
    therefore change an authorization outcome without ever calling
    ``authorize``. ``FirewallSDK.known_capabilities`` exists so readers
    get an immutable view instead.

    Both spellings are checked -- direct attribute access and the
    ``getattr(sdk, "_capability_registry", ...)`` form -- because the
    second is how the access was usually written.
    """

    name = "CONTROL_PLANE_INTEGRITY"
    root, modules, _ = _collect(name)

    if root is None or not modules:
        return unverifiable(
            name,
            "could not locate the firewall package source tree",
        )

    findings: list[str] = []
    parse_failures: list[str] = []
    shared_logic: list[str] = []

    for path in modules:
        label = source.relative_name(path, root)

        if label == "firewall/sdk.py":
            continue

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            parse_failures.append(f"{label}: {error}")
            continue

        if label.startswith("firewall/invariants/"):
            # This package names the forbidden attributes in order to
            # forbid them. Excluding it keeps the check from reporting
            # its own definition as a violation.
            continue

        for node in source.attribute_accesses(
            tree,
            CONTROL_PLANE_STATE,
        ):
            if not source.is_sdk_receiver(node.value):
                # A subsystem's own injected registry, not the SDK's.
                # Dependency injection is the pattern this invariant
                # wants; only reaching *through the SDK* is the problem.
                continue

            findings.append(
                f"{label}:{node.lineno} reaches control-plane state "
                f"{node.attr!r} directly"
            )

        for call, attribute in source.reflective_accesses(
            tree,
            CONTROL_PLANE_STATE,
        ):
            if not source.is_sdk_receiver(call.args[0]):
                continue

            findings.append(
                f"{label}:{call.lineno} reaches control-plane state "
                f"{attribute!r} reflectively"
            )

        for node in source.attribute_accesses(
            tree,
            CONTROL_PLANE_SHARED_LOGIC,
        ):
            if source.is_sdk_receiver(node.value):
                shared_logic.append(
                    f"{label}:{node.lineno} {node.attr}"
                )

    if findings:
        return violated(
            name,
            "control-plane state is reachable from outside "
            "firewall/sdk.py",
            findings=tuple(findings),
            shared_logic=shared_logic,
            parse_failures=parse_failures,
        )

    if parse_failures:
        return unverifiable(
            name,
            "some modules could not be parsed, so the census is "
            "incomplete",
            findings=tuple(parse_failures),
            shared_logic=shared_logic,
        )

    return holds(
        name,
        "no module outside firewall/sdk.py reaches control-plane state",
        shared_logic=shared_logic,
        modules_scanned=len(modules),
    )


def duplicate_provenance_vocabularies() -> tuple[
    tuple[str, ...],
    tuple[str, ...],
]:
    """Enum definitions that restate the canonical provenance vocabulary.

    Returns ``(findings, parse_failures)``. A duplicate is any ``Enum``
    subclass outside :data:`PROVENANCE_OWNERS` whose string member values
    cover the whole canonical set. The subset test is deliberate: an enum
    with these five plus extras is still a competing vocabulary, while an
    enum that happens to contain ``"unknown"`` is not.
    """

    root = source.package_root()

    if root is None:
        return (), ("could not locate the firewall package source tree",)

    findings: list[str] = []
    parse_failures: list[str] = []

    for path in source.source_modules(root):
        label = source.relative_name(path, root)

        if label in PROVENANCE_OWNERS:
            continue

        if label.startswith("firewall/invariants/"):
            continue

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            parse_failures.append(f"{label}: {error}")
            continue

        for node in source.enum_class_defs(tree):
            values = source.enum_member_values(node)

            if PROVENANCE_VALUES <= values:
                findings.append(
                    f"{label}:{node.lineno} {node.name} redefines the "
                    "provenance vocabulary; import "
                    "firewall.platform.Provenance instead"
                )

    return tuple(findings), tuple(parse_failures)



