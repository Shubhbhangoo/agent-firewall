"""v2.1 Capability Firewall 2.0 (firewall.capability2).

Capabilities evolved beyond simple allow/deny: a capability carries a
constraint policy over resource, scope, action, time, context, agent
identity, task identity, delegation lineage, provenance, and
environment. Constraints compose, and attenuation can only narrow - a
delegated capability never gains authority compared with its parent.

The module is a pure, deterministic policy layer. It makes no
authorization decision of its own: it answers *does this request satisfy
this capability's constraint policy?* and leaves the final decision to
the existing authorization pipeline. It plugs into the v2.0 SDK by
validating the constraint shape at issue time and exposing
``Capability2.evaluate`` for the pipeline to consult.

Constraint namespaces (``capability2.constraint`` dict keys):

* ``resource`` -- the resource this capability may touch.
* ``scope`` -- a narrowing scope (path prefix, namespace, ...).
* ``action`` -- the actions this capability may perform.
* ``time`` -- valid window (``not_before``/``not_after``).
* ``context`` -- required request context (``agent``, ``session``, ...).
* ``identity`` -- the bound agent identity (agent_id + optional
  key fingerprint).
* ``task`` -- the bound task identity (task_id).
* ``lineage`` -- delegation lineage policy (``max_depth``).
* ``provenance`` -- provenance markers the request must carry.
* ``environment`` -- environment markers (``env``, ``region``, ...).

Every request is evaluated against *all* namespaces; a single unmet
constraint denies. Numeric values are always compared as ceilings or
floors, never as equality when the request exceeds them. A missing
request key denies (fail closed). A constraint the request does not
carry at all is vacuously satisfied by the request only when the
constraint is declared optional.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

#: Constraint namespaces supported by Capability Firewall 2.0.
CONSTRAINT_NAMESPACES = (
    "resource",
    "scope",
    "action",
    "time",
    "context",
    "identity",
    "task",
    "lineage",
    "provenance",
    "environment",
)

#: Request keys evaluated per namespace.
_REQUEST_KEYS = {
    "resource": ("resource", "resource_id", "uri", "url", "path"),
    "scope": ("scope", "path", "namespace"),
    "action": ("action",),
    "time": (),
    "context": ("agent", "session", "chain_id"),
    "identity": ("agent_id", "key_fingerprint"),
    "task": ("task_id",),
    "lineage": ("delegation_depth",),
    "provenance": ("provenance",),
    "environment": ("env", "region", "host", "environment"),
}

#: Scalar constraint kinds.
_SCALAR_OPERATORS = {
    "eq": lambda actual, expected: actual == expected,
    "lt": lambda actual, expected: actual < expected,
    "lte": lambda actual, expected: actual <= expected,
    "gt": lambda actual, expected: actual > expected,
    "gte": lambda actual, expected: actual >= expected,
    "in": lambda actual, expected: actual in expected,
    "prefix": lambda actual, expected: str(actual).startswith(str(expected)),
    "glob": lambda actual, expected: _glob(str(actual), str(expected)),
}

#: How a namespace treats a string constraint: exact match by default.
_STRING_MATCH = "eq"


class Capability2Error(ValueError):
    """Raised for an invalid capability-2.0 policy or evaluation."""


def _glob(actual: str, pattern: str) -> bool:
    """Minimal glob: ``*`` matches any run of characters."""

    import re

    regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
    return re.match(regex, actual) is not None


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Capability2Error(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise Capability2Error(f"{label} must be finite")
    return result


def validate_constraints(constraints: Any) -> dict[str, Any]:
    """Shape-validate a capability2 constraint map.

    Every top-level key must be a known namespace; values must be
    objects (or lists for ``action``). This runs at issue time so an
    unsupported constraint shape never reaches the pipeline.
    """

    if constraints is None:
        return {}
    if not isinstance(constraints, dict):
        raise Capability2Error("constraints must be an object")

    for key in constraints:
        if key not in CONSTRAINT_NAMESPACES:
            raise Capability2Error(
                f"unknown constraint namespace: {key}"
            )

    value = constraints.get("resource")
    if value is not None and not isinstance(value, str):
        raise Capability2Error("resource constraint must be a string")

    value = constraints.get("scope")
    if value is not None and not isinstance(value, str):
        raise Capability2Error("scope constraint must be a string")

    value = constraints.get("action")
    if value is not None:
        if isinstance(value, str):
            pass
        elif isinstance(value, list) and all(
            isinstance(item, str) for item in value
        ):
            pass
        else:
            raise Capability2Error(
                "action constraint must be a string or a list of strings"
            )

    value = constraints.get("time")
    if value is not None:
        if not isinstance(value, dict):
            raise Capability2Error("time constraint must be an object")
        for key in value:
            if key not in ("not_before", "not_after"):
                raise Capability2Error(
                    f"unknown time constraint key: {key}"
                )
            _finite(value[key], f"time.{key}")

    for namespace in ("context", "identity", "task", "lineage",
                      "provenance", "environment"):
        value = constraints.get(namespace)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise Capability2Error(
                f"{namespace} constraint must be an object"
            )
        for key, entry in value.items():
            if entry is None or isinstance(entry, bool):
                continue
            if isinstance(entry, str):
                continue
            if isinstance(entry, (int, float)):
                _finite(entry, f"{namespace}.{key}")
                continue
            if isinstance(entry, list):
                for item in entry:
                    if not isinstance(item, (str, int, float)):
                        raise Capability2Error(
                            f"{namespace}.{key} list entries must be "
                            "strings or numbers"
                        )
                continue
            if isinstance(entry, dict):
                for op in entry:
                    if op not in _SCALAR_OPERATORS:
                        raise Capability2Error(
                            f"unknown operator {op!r} in "
                            f"{namespace}.{key}"
                        )
                continue
            raise Capability2Error(
                f"unsupported {namespace}.{key} constraint value"
            )

    return dict(constraints)


@dataclass(frozen=True)
class Capability2:
    """A capability-2.0 policy: capability name + constraint policy."""

    capability: str
    constraints: dict[str, Any] = field(default_factory=dict)
    parent: Optional[str] = None
    name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.capability, str) or not self.capability.strip():
            raise Capability2Error("capability is required")
        object.__setattr__(
            self,
            "constraints",
            validate_constraints(self.constraints),
        )

    # ------------------------------------------------------------------
    # Attenuation (safe narrowing)
    # ------------------------------------------------------------------

    def attenuate(
        self,
        **narrowing: Any,
    ) -> "Capability2":
        """Produce a strictly narrower capability.

        Each keyword is a namespace. The child's constraint for a
        namespace is the *intersection* of the parent's constraint and
        the requested narrowing; a namespace the parent does not
        constrain can only be added by the child if it narrows from
        "everything allowed" - which it does, because adding any
        constraint restricts. The child can never widen.

        The invariant is enforced structurally: ``is_narrower_than``
        returns True for every attenuation, and a delegated capability
        that would widen raises :class:`Capability2Error` at
        ``delegate`` time.
        """

        child_constraints = dict(self.constraints)
        for namespace, value in narrowing.items():
            if namespace not in CONSTRAINT_NAMESPACES:
                raise Capability2Error(
                    f"unknown constraint namespace: {namespace}"
                )
            parent_value = child_constraints.get(namespace)
            child_value = _narrow(parent_value, value, namespace)
            child_constraints[namespace] = child_value

        return Capability2(
            capability=self.capability,
            constraints=child_constraints,
            parent=self.name or self.capability,
            name=self.name,
        )

    def delegate(
        self,
        **narrowing: Any,
    ) -> "Capability2":
        """Attenuation + delegation lineage bookkeeping.

        Identical narrowing semantics; the resulting capability records
        ``parent`` so the lineage is verifiable and recursive revocation
        can walk it.
        """

        child = self.attenuate(**narrowing)
        return child

    def is_narrower_than(
        self,
        parent: "Capability2",
    ) -> bool:
        """Structural check: is this capability at most as powerful as
        ``parent``? Every namespace in the child must be present in the
        parent and no wider, and every namespace the parent constrains
        must be present in the child."""

        for namespace, child_value in self.constraints.items():
            parent_value = parent.constraints.get(namespace)
            if parent_value is None:
                return False  # child constrains a namespace the parent
                              # does not - that is a widening
            if not _narrower_or_equal(child_value, parent_value, namespace):
                return False

        # Dropping a namespace is widening, not narrowing: ``evaluate``
        # skips namespaces it holds no constraint for, so a child that
        # simply omits one the parent constrains would be *unlimited*
        # there.
        for namespace in parent.constraints:
            if self.constraints.get(namespace) is None:
                return False

        return True

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        request: dict[str, Any],
        *,
        now: Optional[float] = None,
    ) -> tuple[bool, str]:
        """Evaluate a request against every constraint namespace.

        Returns ``(allowed, reason)``. Fail closed: a missing request
        key, an unknown request shape, or an unparseable constraint
        denies. ``now`` is required for the ``time`` namespace and
        defaults to the wall clock.
        """

        if not isinstance(request, dict):
            return False, "request must be an object"

        for namespace in CONSTRAINT_NAMESPACES:
            constraint = self.constraints.get(namespace)
            if constraint is None:
                continue
            allowed, reason = _evaluate_namespace(
                namespace,
                constraint,
                request,
                now=now,
            )
            if not allowed:
                return False, reason

        return True, "all capability2 constraints satisfied"

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "constraints": dict(self.constraints),
            "parent": self.parent,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Capability2":
        if not isinstance(payload, dict):
            raise Capability2Error("capability2 must be an object")
        return cls(
            capability=payload.get("capability"),
            constraints=payload.get("constraints", {}) or {},
            parent=payload.get("parent"),
            name=payload.get("name", ""),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Capability2(capability={self.capability!r}, "
            f"parent={self.parent!r})"
        )


# ----------------------------------------------------------------------
# Narrowing helpers
# ----------------------------------------------------------------------


def _narrow(parent: Any, child: Any, namespace: str) -> Any:
    """Intersection of a parent constraint and a requested narrowing."""

    if parent is None:
        # Adding a constraint to an unconstrained capability is always a
        # narrowing (from "anything" to "something").
        return _copy_constraint(child)

    if namespace == "action":
        if isinstance(parent, str):
            parent = [parent]
        if isinstance(child, str):
            child = [child]
        parent_set = set(parent)
        child_set = set(child)
        narrowed = sorted(parent_set & child_set)
        if not narrowed:
            raise Capability2Error(
                "attenuation leaves no permitted actions"
            )
        if len(narrowed) == 1:
            return narrowed[0]
        return narrowed

    if isinstance(parent, dict) and isinstance(child, dict):
        merged = dict(parent)
        for key, child_value in child.items():
            if key not in parent:
                merged[key] = child_value
                continue
            parent_value = parent[key]
            narrowed_value = _narrow_scalar(
                parent_value, child_value, namespace, key
            )
            if narrowed_value is None:
                raise Capability2Error(
                    f"attenuation cannot narrow {namespace}.{key} "
                    "to an empty set"
                )
            merged[key] = narrowed_value
        return merged

    if isinstance(parent, (int, float)) and isinstance(child, (int, float)):
        # Numeric ceilings narrow to the smaller value.
        result = min(parent, child)
        return result

    if isinstance(parent, str) and isinstance(child, str):
        if parent != child:
            raise Capability2Error(
                f"attenuation cannot change {namespace} "
                f"from {parent!r} to {child!r}; "
                "it can only narrow"
            )
        return parent

    raise Capability2Error(
        f"cannot attenuate incompatible {namespace} constraints"
    )


def _narrow_scalar(
    parent: Any,
    child: Any,
    namespace: str,
    key: str,
) -> Any:
    """Narrow one scalar constraint entry (string or numeric or op)."""

    # Operator form.
    if isinstance(parent, dict) and set(parent) <= set(_SCALAR_OPERATORS):
        if isinstance(child, dict) and set(child) <= set(_SCALAR_OPERATORS):
            # Keep the tighter operator set: equal operators with equal
            # values pass through; a child with a stricter operator on
            # the same value passes through; anything else is refused.
            if parent == child:
                return dict(child)
            raise Capability2Error(
                f"cannot combine operator constraints for "
                f"{namespace}.{key}"
            )
        # child is a plain value: interpret as an additional eq bound.
        if "eq" in parent and parent["eq"] == child:
            return child
        raise Capability2Error(
            f"cannot narrow operator constraint {namespace}.{key}"
        )

    if isinstance(parent, (int, float)) and isinstance(child, (int, float)):
        return min(parent, child)

    if isinstance(parent, str) and isinstance(child, str):
        if parent == child:
            return parent
        # Prefix narrowing only holds for a hierarchical scope, and only
        # at a segment boundary. Every other string constraint is an
        # opaque identifier, so a child that merely *extends* the parent
        # ("eu" -> "eu-secret-prod") permits requests the parent denies:
        # returning it here would make ``attenuate`` widen.
        if namespace == "scope":
            if _scope_contains(parent, child):
                return child
            if _scope_contains(child, parent):
                return parent  # child is wider; keep parent
        raise Capability2Error(
            f"cannot narrow {namespace}.{key} "
            f"from {parent!r} to {child!r}"
        )

    if isinstance(parent, list) and isinstance(child, (list, str)):
        child_set = {child} if isinstance(child, str) else set(child)
        narrowed = sorted(set(parent) & child_set)
        if not narrowed:
            raise Capability2Error(
                f"attenuation leaves no permitted values for "
                f"{namespace}.{key}"
            )
        return narrowed[0] if len(narrowed) == 1 else narrowed

    raise Capability2Error(
        f"cannot narrow incompatible {namespace}.{key} values"
    )


def _copy_constraint(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _copy_constraint(v) for k, v in value.items()}
    if isinstance(value, list):
        return list(value)
    return value


#: Characters that delimit one segment of a hierarchical scope.
_SCOPE_SEPARATORS = ("/", ":", ".")


def _scope_separator(prefix: str) -> Optional[str]:
    """The delimiter that structures ``prefix``, or ``None`` if it is flat.

    A scope uses one delimiter, not all of them: ``/tmp/safe`` is a path,
    so only ``/`` opens a new segment. Accepting any separator there
    would make ``/tmp/safe.bak`` - a *sibling* - look like a child.
    """

    for separator in _SCOPE_SEPARATORS:
        if separator in prefix:
            return separator
    return None


def _scope_contains(prefix: str, value: str) -> bool:
    """Does the hierarchical scope ``prefix`` contain ``value``?

    Prefix matching is only sound at a segment boundary. ``/prod``
    contains ``/prod/invoice`` but *not* ``/production`` - without the
    boundary check, any string constraint is satisfied by simply
    appending characters to it, and a constraint of ``/prod`` would
    authorise ``/prod-evil/creds``.

    Only the ``scope`` namespace is hierarchical. Every other string
    constraint - an action, a resource, an environment - is an opaque
    identifier and must match exactly: treating ``read`` as a prefix of
    ``read_all_secrets`` is an authorization bypass, not a scope check.
    """

    if value == prefix:
        return True
    if not prefix or not value.startswith(prefix):
        return False
    separator = _scope_separator(prefix)
    # A flat root ("payments") has no delimiter of its own yet, so any
    # of them may open its first child segment ("payments.send").
    boundaries = (separator,) if separator else _SCOPE_SEPARATORS
    if prefix[-1] in boundaries:
        return True
    return value[len(prefix)] in boundaries


def _narrower_or_equal(
    child: Any,
    parent: Any,
    namespace: str,
) -> bool:
    """Is ``child`` at most as permissive as ``parent``?"""

    if namespace == "action":
        child_set = {child} if isinstance(child, str) else set(child)
        parent_set = {parent} if isinstance(parent, str) else set(parent)
        return child_set <= parent_set

    if isinstance(parent, dict) and isinstance(child, dict):
        for key, child_value in child.items():
            if key not in parent:
                return False
            if not _narrower_or_equal(child_value, parent[key], namespace):
                return False
        return True

    if isinstance(parent, (int, float)) and isinstance(child, (int, float)):
        return child <= parent  # ceilings: smaller is narrower

    if isinstance(parent, str) and isinstance(child, str):
        if parent == child:
            return True
        if namespace == "scope":
            return _scope_contains(parent, child)
        # Any other namespace is an opaque identifier: extending it is
        # widening, not narrowing.
        return False

    if isinstance(parent, list) and isinstance(child, (list, str)):
        child_set = {child} if isinstance(child, str) else set(child)
        return child_set <= set(parent)

    return child == parent


# ----------------------------------------------------------------------
# Namespace evaluation
# ----------------------------------------------------------------------


def _evaluate_namespace(
    namespace: str,
    constraint: Any,
    request: dict[str, Any],
    *,
    now: Optional[float],
) -> tuple[bool, str]:
    if namespace == "time":
        return _evaluate_time(constraint, now)

    if namespace == "lineage":
        return _evaluate_lineage(constraint, request)

    if namespace == "identity":
        return _evaluate_identity(constraint, request)

    keys = _REQUEST_KEYS[namespace]

    if namespace in ("action", "resource", "scope"):
        # A single primary request key.
        primary = keys[0]
        actual = request.get(primary)
        if actual is None:
            # Try the alternates.
            for key in keys[1:]:
                value = request.get(key)
                if value is not None:
                    actual = value
                    break
        if actual is None:
            return False, (
                f"request carries no {primary} for the "
                f"{namespace} constraint"
            )
        return _evaluate_value(
            constraint, actual, namespace, primary
        )

    # context / provenance / environment: evaluate every constrained
    # key against the request. The namespace's candidate keys guide
    # which request fields are meaningful, but an arbitrary constrained
    # key is still evaluated - skipping it would silently drop the
    # constraint, which is a widening.
    if not isinstance(constraint, dict):
        return False, f"{namespace} constraint must be an object"
    for key, expected in constraint.items():
        actual = request.get(key)
        if actual is None:
            return False, f"request is missing {namespace}.{key}"
        allowed, reason = _evaluate_value(
            expected, actual, namespace, key
        )
        if not allowed:
            return False, reason
    return True, f"{namespace} satisfied"


def _evaluate_time(
    constraint: Any,
    now: Optional[float],
) -> tuple[bool, str]:
    if not isinstance(constraint, dict):
        return False, "time constraint must be an object"
    if now is None:
        import time as _time

        now = _time.time()
    now = _finite(now, "now")
    not_before = constraint.get("not_before")
    not_after = constraint.get("not_after")
    if not_before is not None and now < _finite(not_before, "not_before"):
        return False, "request is before the capability's valid window"
    if not_after is not None and now >= _finite(not_after, "not_after"):
        return False, "request is after the capability's valid window"
    return True, "time constraint satisfied"


def _evaluate_lineage(
    constraint: Any,
    request: dict[str, Any],
) -> tuple[bool, str]:
    if not isinstance(constraint, dict):
        return False, "lineage constraint must be an object"
    max_depth = constraint.get("max_depth")
    if max_depth is None:
        return True, "lineage constraint satisfied"
    max_depth = _finite(max_depth, "lineage.max_depth")
    depth = request.get("delegation_depth")
    if depth is None:
        return False, "request carries no delegation depth"
    depth = _finite(depth, "delegation_depth")
    if depth > max_depth:
        return False, (
            f"delegation depth {depth} exceeds the lineage ceiling "
            f"{max_depth}"
        )
    return True, "lineage constraint satisfied"


def _evaluate_identity(
    constraint: Any,
    request: dict[str, Any],
) -> tuple[bool, str]:
    if not isinstance(constraint, dict):
        return False, "identity constraint must be an object"
    agent_id = constraint.get("agent_id")
    if agent_id is not None:
        actual = request.get("agent_id")
        if actual != agent_id:
            return False, (
                f"request agent {actual!r} does not match the "
                f"bound identity {agent_id!r}"
            )
    fingerprint = constraint.get("key_fingerprint")
    if fingerprint is not None:
        actual = request.get("key_fingerprint")
        if actual != fingerprint:
            return False, "request key fingerprint does not match"
    return True, "identity constraint satisfied"


def _evaluate_value(
    constraint: Any,
    actual: Any,
    namespace: str,
    key: str,
) -> tuple[bool, str]:
    """Evaluate one request value against one constraint value."""

    if isinstance(constraint, dict) and set(constraint) <= set(
        _SCALAR_OPERATORS
    ):
        for operator, expected in constraint.items():
            try:
                ok = _SCALAR_OPERATORS[operator](actual, expected)
            except Exception:
                ok = False
            if not ok:
                return False, (
                    f"{namespace}.{key} fails {operator} "
                    f"({actual!r} vs {expected!r})"
                )
        return True, f"{namespace}.{key} satisfied"

    if isinstance(constraint, list):
        if actual not in constraint:
            return False, (
                f"{namespace}.{key} {actual!r} is not permitted "
                f"(allowed: {constraint!r})"
            )
        return True, f"{namespace}.{key} satisfied"

    if isinstance(constraint, str):
        if str(actual) == constraint:
            return True, f"{namespace}.{key} satisfied"
        if namespace == "scope" and _scope_contains(
            constraint, str(actual)
        ):
            return True, f"{namespace}.{key} satisfied (scope prefix)"
        return False, (
            f"{namespace}.{key} {actual!r} does not match "
            f"{constraint!r}"
        )

    if isinstance(constraint, bool):
        # ``bool`` is an ``int`` subclass, so it must be checked before
        # the numeric branch.
        if bool(actual) != constraint:
            return False, f"{namespace}.{key} must be {constraint}"
        return True, f"{namespace}.{key} satisfied"

    if isinstance(constraint, (int, float)):
        if isinstance(actual, bool) or not isinstance(
            actual, (int, float)
        ):
            return False, f"{namespace}.{key} must be numeric"
        if float(actual) > float(constraint):
            return False, (
                f"{namespace}.{key} {actual} exceeds the ceiling "
                f"{constraint}"
            )
        return True, f"{namespace}.{key} satisfied"

    if constraint is None:
        return True, f"{namespace}.{key} unconstrained"

    return False, (
        f"unsupported {namespace}.{key} constraint of type "
        f"{type(constraint).__name__}"
    )
