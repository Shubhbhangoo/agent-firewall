"""The authority envelope: a faithful projection of what a chain admits.

An envelope is a *representation*, not a decision. It exists because
v2.3 could answer "is this request allowed?" exactly and could not answer
"what is this grant allowed to do?" at all -- the second question had no
type, so an operator narrowing a grant, or an invariant checking that a
child did not widen, had nothing to compare.

What makes the projection safe is that every dimension is a projection of
something the canonical boundary already enforces. Nothing here publishes
a bound that ``FirewallSDK.authorize()`` does not hold. The local
admission test the boundary applies to a single capability is, exactly:

    local_admits(k, a, r) at t
        <=>  k.tool is None or k.tool == a          (_check_tool_binding)
         and matches(k.capability, a)               (namespace)
         and _check_constraints(k.constraints, r)
         and k.issued_at <= t < k.expires_at        (clock, when supplied)

and ``_gate_cryptographic_authority`` applies it to the requested
capability *and every resolved ancestor*, against the same action and
request. So effective authority is already an intersection over the
chain, and the envelope is its per-dimension meet:

    Envelope(c) = MEET { LocalEnvelope(k) : k in chain(c) }

**Soundness, and the one direction that is claimed.**

    Envelope(c).excludes(a, r, t)  =>  authorize(c, a, r) denies at t

The converse is *not* claimed and is not true: the envelope meets each
dimension independently, so a pair of constraints that no single request
can satisfy jointly may still leave every dimension individually
satisfiable. Therefore an envelope may be used to deny early and may
never be used to allow. The two method names are chosen so that misuse
reads wrong: :meth:`AuthorityEnvelope.excludes` returns a reason, and
:meth:`AuthorityEnvelope.may_admit` says "may", because that is all it
establishes.

**Monotonicity, by construction.** ``chain(child) = [child] +
chain(parent)`` for a registered lineage edge, so ``Envelope(child) =
LocalEnvelope(child) MEET Envelope(parent)``, and a meet over more terms
is never larger. This holds whether or not the child's own constraints
narrowed -- it is a property of the definition, not an assumption about
the input.

**Every failure is bottom.** An envelope that cannot be computed admits
nothing. That is safe precisely because the envelope never allows.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

from firewall.authorization import (
    _check_constraints,
    _is_composition_rule,
    _request_key,
)
from firewall.capability import Capability, capability_fingerprint
from firewall.namespace import matches

#: Constraint keys that ``_check_constraints`` routes straight into the
#: policy evaluator without deriving a request key from them.
COMPOSITION_KEYS = frozenset(
    {
        "and",
        "or",
        "not",
    }
)

#: Comparison operators a constraint value may carry as a nested dict.
#: Present here only so this module can *recognise* them; they are never
#: re-implemented, they are handed back to ``_check_constraints``.
OPERATOR_KEYS = frozenset(
    {
        "eq",
        "neq",
        "in",
        "not_in",
        "gte",
        "lte",
        "contains",
    }
)

_EMPTY: Mapping[str, Any] = MappingProxyType({})


def _freeze(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(values))
@dataclass(frozen=True)
class BudgetBound:
    """Remaining budget, when a :class:`SecurityContext` is attached.

    ``readable=False`` means the sidecar state could not be read. That is
    represented as *exhausted* rather than unlimited: an unreadable
    budget may be a spent one, and unknown is not trusted.
    """

    remaining_actions: Optional[int] = None
    remaining_amount: Optional[float] = None
    readable: bool = True

    def excludes(self, request: Mapping[str, Any]) -> Optional[str]:
        if not self.readable:
            return "budget_unreadable"

        if self.remaining_actions is not None and self.remaining_actions <= 0:
            return "budget_actions_exhausted"

        if self.remaining_amount is None:
            return None

        amount = request.get("amount")

        if amount is None:
            return None

        if not isinstance(amount, (int, float)):
            return "budget_amount_not_numeric"

        # Only floats can be non-finite. Converting first would raise
        # ``OverflowError`` on an int too large for a float -- and such an
        # int is ordered exactly against a float bound in Python, so the
        # comparison below answers it correctly without a conversion.
        if isinstance(amount, float) and not math.isfinite(amount):
            return "budget_amount_not_finite"

        if amount > self.remaining_amount:
            return "budget_amount_exceeded"

        return None

    def is_subset_of(self, other: "BudgetBound") -> bool:
        if not self.readable:
            return True

        if not other.readable:
            return False

        return _le(
            self.remaining_actions,
            other.remaining_actions,
        ) and _le(
            self.remaining_amount,
            other.remaining_amount,
        )
def _le(smaller: Optional[float], larger: Optional[float]) -> bool:
    """``smaller`` is at most ``larger``, with ``None`` meaning unbounded."""

    if larger is None:
        return True

    if smaller is None:
        return False

    return smaller <= larger


def _meet_budget(
    left: Optional[BudgetBound],
    right: Optional[BudgetBound],
) -> Optional[BudgetBound]:
    if left is None:
        return right

    if right is None:
        return left

    if not (left.readable and right.readable):
        return BudgetBound(readable=False)

    return BudgetBound(
        remaining_actions=_min_optional(
            left.remaining_actions,
            right.remaining_actions,
        ),
        remaining_amount=_min_optional(
            left.remaining_amount,
            right.remaining_amount,
        ),
    )


def _min_optional(left, right):
    if left is None:
        return right

    if right is None:
        return left

    return min(left, right)
@dataclass(frozen=True)
class ConstraintBound:
    """The v1 constraint dict, met across a chain.

    Keyed by *request* key throughout, because that is what
    ``_check_constraints`` looks up: ``amount_max`` and ``amount_min``
    both bound the request's ``amount``, so a ceiling and a floor on the
    same quantity are comparable and can be shown to conflict.

    ``opaque`` holds the fragments this module refuses to approximate --
    policy compositions, comparison-operator dicts, nested dicts, and any
    pair of values whose meet is not one of the four known shapes. They
    are not dropped and they are not guessed at: they are carried and
    evaluated by handing each one back to ``_check_constraints``, which is
    exact. Accumulating them is what keeps a child's bound a subset of
    its parent's.
    """

    ceilings: Mapping[str, float] = _EMPTY
    floors: Mapping[str, float] = _EMPTY
    exact: Mapping[str, Any] = _EMPTY
    enumerations: Mapping[str, tuple] = _EMPTY
    opaque: tuple[tuple[str, Any], ...] = ()
    required: frozenset[str] = frozenset()
    reasons: tuple[str, ...] = ()

    @property
    def bottom(self) -> bool:
        """No request can satisfy this bound."""

        return bool(self.reasons)
    def excludes(self, request: Optional[Mapping[str, Any]]) -> Optional[str]:
        """Why no admission is possible, or ``None`` if none can be shown."""

        if self.bottom:
            return f"constraints_unsatisfiable:{self.reasons[0]}"

        data = {} if request is None else request

        if not isinstance(data, Mapping):
            return "request_not_a_mapping"

        for key in sorted(self.required):
            if key not in data:
                return f"request_key_missing:{key}"

        for key, ceiling in self.ceilings.items():
            failure = _numeric_failure(data[key], key)

            if failure is not None:
                return failure

            # Compared without converting. Python orders an int against a
            # float exactly and without overflowing, which matters because
            # ``float(10**400)`` raises -- and an exception out of an
            # envelope read would take down the invariant sweep and the
            # console rather than answering the question.
            if data[key] > ceiling:
                return f"ceiling_exceeded:{key}"

        for key, floor in self.floors.items():
            failure = _numeric_failure(data[key], key)

            if failure is not None:
                return failure

            if data[key] < floor:
                return f"floor_unmet:{key}"

        for key, expected in self.exact.items():
            if data[key] != expected:
                return f"exact_mismatch:{key}"

        for key, allowed in self.enumerations.items():
            try:
                admitted = data[key] in allowed
            except TypeError:
                return f"enumeration_unorderable:{key}"

            if not admitted:
                return f"enumeration_excluded:{key}"

        return self._opaque_failure(data)
    def _opaque_failure(self, data: Mapping[str, Any]) -> Optional[str]:
        """Evaluate each carried fragment with the boundary's own checker.

        Exact rather than approximate, and deliberately so: a fragment
        this module cannot meet is a fragment it must not reason about.
        A raising fragment is a failure, not a pass.
        """

        for key, fragment in self.opaque:
            try:
                admitted = _check_constraints(
                    {key: fragment},
                    dict(data),
                )
            except Exception:  # noqa: BLE001 - unevaluable is not admitted
                return f"constraint_unevaluable:{key}"

            if not admitted:
                return f"constraint_denied:{key}"

        return None

    def is_subset_of(self, other: "ConstraintBound") -> bool:
        if self.bottom:
            return True

        if other.bottom:
            return False

        if not self.required >= other.required:
            return False

        for key, ceiling in other.ceilings.items():
            if key not in self.ceilings or self.ceilings[key] > ceiling:
                return False

        for key, floor in other.floors.items():
            if key not in self.floors or self.floors[key] < floor:
                return False

        for key, expected in other.exact.items():
            if key not in self.exact or self.exact[key] != expected:
                return False

        for key, allowed in other.enumerations.items():
            if key not in self.enumerations:
                return False

            if not all(
                _member_of(member, allowed)
                for member in self.enumerations[key]
            ):
                return False

        return _multiset_contains(self.opaque, other.opaque)
def _multiset_contains(
    haystack: Sequence[tuple[str, Any]],
    needles: Sequence[tuple[str, Any]],
) -> bool:
    """Every fragment in ``needles`` appears at least as often in ``haystack``.

    Fragments are not hashable in general (they are dicts), so this is a
    linear scan against a consumed copy rather than a set operation.
    """

    remaining = list(haystack)

    for needle in needles:
        for index, candidate in enumerate(remaining):
            if candidate[0] == needle[0] and candidate[1] == needle[1]:
                del remaining[index]
                break
        else:
            return False

    return True


def _numeric_failure(value: Any, key: str) -> Optional[str]:
    """Mirror the boundary's numeric admission test, including NaN.

    ``_check_constraints`` rejects a non-numeric actual against a numeric
    bound, and rejects a non-finite one -- because ``nan > x`` and ``nan <
    x`` are both False, NaN would otherwise satisfy every ceiling and
    every floor at once.

    ``bool`` is deliberately *not* excluded here even though it is a
    subclass of ``int`` and comparing it against a money ceiling is
    nonsense. The boundary admits it, and an envelope that excluded what
    the boundary admits would be unsound in the one direction this module
    claims. The place to reject it, if it is ever rejected, is
    ``_check_constraints``; then this follows.

    An int too large to convert to a float is admitted here for the same
    reason: the boundary orders it exactly against the bound and denies or
    allows on the answer, so the envelope must not pre-empt that with an
    exclusion of its own -- and ``math.isfinite`` would raise
    ``OverflowError`` rather than return an answer at all.
    """

    if not isinstance(value, (int, float)):
        return f"request_value_not_numeric:{key}"

    if isinstance(value, float) and not math.isfinite(value):
        return f"request_value_not_finite:{key}"

    return None
def local_constraint_bound(
    constraints: Optional[Mapping[str, Any]],
) -> ConstraintBound:
    """Classify one capability's constraint dict into the four known shapes.

    Anything that is not a numeric ceiling, numeric floor, bare scalar or
    enumeration becomes an opaque fragment. The classification mirrors
    ``_check_constraints`` branch for branch, including which keys make a
    request key mandatory: every constraint key does, except a top-level
    ``and``/``or``/``not`` composition, which the evaluator reads against
    the whole request.
    """

    if constraints is None:
        return ConstraintBound()

    if not isinstance(constraints, Mapping):
        return ConstraintBound(reasons=("constraints_not_a_mapping",))

    ceilings: dict[str, float] = {}
    floors: dict[str, float] = {}
    exact: dict[str, Any] = {}
    enumerations: dict[str, tuple] = {}
    opaque: list[tuple[str, Any]] = []
    required: set[str] = set()

    for key, expected in constraints.items():
        if not isinstance(key, str):
            return ConstraintBound(reasons=("constraint_key_not_a_string",))

        if key in COMPOSITION_KEYS:
            opaque.append((key, expected))
            continue

        request_key = _request_key(key)
        required.add(request_key)

        if isinstance(expected, Mapping):
            opaque.append((key, expected))
            continue

        if _is_finite_number(expected):
            if key.endswith("_max"):
                ceilings[request_key] = float(expected)
            elif key.endswith("_min"):
                floors[request_key] = float(expected)
            else:
                exact[request_key] = expected

            continue

        if isinstance(expected, (list, tuple, set, frozenset)):
            enumerations[request_key] = tuple(expected)
            continue

        if isinstance(expected, (bool, int, float)):
            # A bool bound, or a non-finite one. ``_check_constraints``
            # sends both down its numeric branch, where ``actual > inf``
            # and ``actual > nan`` are False and therefore admit, and
            # ``actual > True`` compares against 1. Approximating any of
            # that would make the envelope stricter than the boundary in
            # one case and looser in another, so it is carried verbatim
            # and evaluated exactly instead.
            opaque.append((key, expected))
            continue

        exact[request_key] = expected

    return _bound(ceilings, floors, exact, enumerations, tuple(opaque), required)


def _is_finite_number(value: Any) -> bool:
    """Is ``value`` usable as a numeric point in the envelope's lattice?

    The lattice stores bounds as floats, so an int outside the float range
    is not usable even though it is mathematically finite -- and asking
    ``math.isfinite`` about it raises ``OverflowError``. Answering False
    routes it to the opaque fragments, where "cannot reason about this"
    widens the envelope rather than narrowing it. Widening is the sound
    direction: the envelope may admit what the boundary denies, never the
    reverse.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False

    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False
def _bound(
    ceilings: Mapping[str, float],
    floors: Mapping[str, float],
    exact: Mapping[str, Any],
    enumerations: Mapping[str, tuple],
    opaque: tuple[tuple[str, Any], ...],
    required: set[str],
    reasons: tuple[str, ...] = (),
) -> ConstraintBound:
    """Assemble a bound and detect the pairs no request can satisfy.

    Each conflict below is bottom only because the *boundary* denies every
    request in that situation. Bottom is a claim that admission is
    impossible, so an over-eager conflict rule would make the envelope
    exclude what ``authorize`` allows -- unsound in the one direction this
    module claims.
    """

    findings = list(reasons)

    for key, ceiling in ceilings.items():
        floor = floors.get(key)

        if floor is not None and floor > ceiling:
            findings.append(f"floor_above_ceiling:{key}")

    for key, expected in exact.items():
        if _is_finite_number(expected):
            value = float(expected)

            if key in ceilings and value > ceilings[key]:
                findings.append(f"exact_above_ceiling:{key}")

            if key in floors and value < floors[key]:
                findings.append(f"exact_below_floor:{key}")

        if key in enumerations:
            try:
                present = expected in enumerations[key]
            except TypeError:
                present = False

            if not present:
                findings.append(f"exact_outside_enumeration:{key}")

    findings.extend(_enumeration_findings(ceilings, floors, enumerations))

    return ConstraintBound(
        ceilings=_freeze(ceilings),
        floors=_freeze(floors),
        exact=_freeze(exact),
        enumerations=_freeze(enumerations),
        opaque=opaque,
        required=frozenset(required),
        reasons=tuple(findings),
    )
def _enumeration_findings(
    ceilings: Mapping[str, float],
    floors: Mapping[str, float],
    enumerations: Mapping[str, tuple],
) -> list[str]:
    findings: list[str] = []

    for key, members in enumerations.items():
        if not members:
            findings.append(f"enumeration_empty:{key}")
            continue

        ceiling = ceilings.get(key)
        floor = floors.get(key)

        if ceiling is None and floor is None:
            continue

        if not any(
            _numeric_failure(member, key) is None
            and (ceiling is None or float(member) <= ceiling)
            and (floor is None or float(member) >= floor)
            for member in members
        ):
            findings.append(f"enumeration_outside_bounds:{key}")

    return findings


def meet_constraint_bounds(
    left: ConstraintBound,
    right: ConstraintBound,
) -> ConstraintBound:
    """The per-key meet: tighter ceiling, higher floor, narrower enumeration."""

    ceilings = dict(left.ceilings)
    for key, value in right.ceilings.items():
        ceilings[key] = min(ceilings[key], value) if key in ceilings else value

    floors = dict(left.floors)
    for key, value in right.floors.items():
        floors[key] = max(floors[key], value) if key in floors else value

    exact = dict(left.exact)
    conflicts: list[str] = []
    for key, value in right.exact.items():
        if key in exact and exact[key] != value:
            conflicts.append(f"exact_conflict:{key}")
            continue

        exact[key] = value

    enumerations = dict(left.enumerations)
    for key, members in right.enumerations.items():
        if key not in enumerations:
            enumerations[key] = members
            continue

        allowed = members
        enumerations[key] = tuple(
            member for member in enumerations[key] if _member_of(member, allowed)
        )

    return _bound(
        ceilings,
        floors,
        exact,
        enumerations,
        left.opaque + right.opaque,
        set(left.required) | set(right.required),
        left.reasons + right.reasons + tuple(conflicts),
    )
def _member_of(value: Any, members: Sequence[Any]) -> bool:
    """Containment that cannot raise.

    Enumerations come from signed constraint dicts, which JSON round-trips
    permit to contain lists and dicts. ``value in members`` on an
    unorderable pair raises, and a raising membership test is not a
    successful one.
    """

    try:
        return value in members
    except TypeError:
        return False
@dataclass(frozen=True)
class AuthorityEnvelope:
    """What a capability chain can admit, dimension by dimension.

    There is deliberately no ``allowed`` field and no ``__bool__``. An
    envelope is not a verdict and must not be usable as one.
    """

    #: Namespace patterns every action must match -- one per chain member.
    patterns: tuple[str, ...] = ()
    #: The single bound tool, or ``None`` for the legacy namespace
    #: behaviour. Two distinct bound tools in a chain make the envelope
    #: bottom, since no action can equal both.
    tool: Optional[str] = None
    #: Half-open ``[start, end)``, the intersection of the members' windows.
    window: tuple[float, float] = (float("-inf"), float("inf"))
    constraints: ConstraintBound = ConstraintBound()
    #: Resolved chain length, and the ceiling the boundary enforces on it.
    depth: int = 1
    depth_ceiling: Optional[int] = None
    issuers: tuple[str, ...] = ()
    #: ``None`` when trust could not be established either way.
    issuer_trusted: Optional[bool] = None
    revoked: bool = False
    budget: Optional[BudgetBound] = None
    #: Fingerprints of the chain members, nearest first, for explanation.
    members: tuple[str, ...] = ()
    #: Non-empty means bottom: this envelope admits nothing.
    reasons: tuple[str, ...] = ()

    @property
    def bottom(self) -> bool:
        return bool(self.reasons) or self.constraints.bottom

    def __bool__(self) -> bool:
        raise TypeError(
            "an AuthorityEnvelope is not a decision; call excludes() to "
            "learn what it refuses, or FirewallSDK.authorize() to decide"
        )
    def excludes(
        self,
        action: Optional[str] = None,
        request: Optional[Mapping[str, Any]] = None,
        now: Optional[float] = None,
    ) -> Optional[str]:
        """The reason this envelope refuses the request, or ``None``.

        ``None`` establishes nothing. It means no dimension could be shown
        to refuse, which is not the same as the boundary allowing.
        """

        if self.reasons:
            return f"envelope_bottom:{self.reasons[0]}"

        if self.revoked:
            return "revoked"

        if self.issuer_trusted is False:
            return "issuer_untrusted"

        if self.depth_ceiling is not None and self.depth > self.depth_ceiling:
            return "delegation_depth_exceeded"

        if now is not None:
            if not isinstance(now, (int, float)) or not math.isfinite(float(now)):
                return "clock_unusable"

            if float(now) < self.window[0]:
                return "not_yet_valid"

            if float(now) >= self.window[1]:
                return "expired"

        if action is not None:
            if self.tool is not None and self.tool != action:
                return "tool_binding_denied"

            for pattern in self.patterns:
                if not matches(pattern, action):
                    return f"namespace_denied:{pattern}"

        failure = self.constraints.excludes(request)

        if failure is not None:
            return failure

        if self.budget is not None:
            return self.budget.excludes({} if request is None else request)

        return None

    def may_admit(
        self,
        action: Optional[str] = None,
        request: Optional[Mapping[str, Any]] = None,
        now: Optional[float] = None,
    ) -> bool:
        """"May", not "does". This is not an authorization."""

        return self.excludes(action, request, now) is None
    def is_subset_of(self, other: "AuthorityEnvelope") -> bool:
        """Does ``self`` admit at most what ``other`` admits?

        Compares the *chain-meet* dimensions. ``issuer_trusted`` is
        deliberately excluded: ``_gate_issuer`` checks only the requested
        capability's issuer, not its ancestors', so issuer trust is a
        property of the head of the chain rather than a meet over it, and
        comparing it here would report a violation for a state the boundary
        genuinely treats asymmetrically. Every chain built through
        ``delegate`` or ``attenuate`` carries the parent's issuer forward,
        so the two coincide in practice; a hand-registered edge joining two
        issuers is the only case where they part.

        ``depth`` is compared in the direction that makes it monotone: a
        longer chain under the same ceiling is more excluded, not less.
        """

        if self.bottom:
            return True

        if other.bottom:
            return False

        if not set(self.patterns) >= set(other.patterns):
            return False

        if other.tool is not None and self.tool != other.tool:
            return False

        if self.window[0] < other.window[0] or self.window[1] > other.window[1]:
            return False

        if self.depth < other.depth:
            return False

        if not _le(self.depth_ceiling, other.depth_ceiling):
            return False

        if other.revoked and not self.revoked:
            return False

        if not self.constraints.is_subset_of(other.constraints):
            return False

        if other.budget is not None:
            if self.budget is None:
                return False

            if not self.budget.is_subset_of(other.budget):
                return False

        return True
    def describe(self) -> dict:
        """A JSON-shaped rendering, for §17 explanations and the console.

        Derived entirely from the fields above. There is no narration and
        no model output anywhere in it -- an explanation that cannot be
        recomputed from state is not an explanation.
        """

        return {
            "bottom": self.bottom,
            "reasons": list(self.reasons),
            "patterns": list(self.patterns),
            "tool": self.tool,
            "window": {
                "start": self.window[0],
                "end": self.window[1],
            },
            "depth": self.depth,
            "depth_ceiling": self.depth_ceiling,
            "issuers": list(self.issuers),
            "issuer_trusted": self.issuer_trusted,
            "revoked": self.revoked,
            "members": list(self.members),
            "constraints": {
                "ceilings": dict(self.constraints.ceilings),
                "floors": dict(self.constraints.floors),
                "exact": dict(self.constraints.exact),
                "enumerations": {
                    key: list(value)
                    for key, value in self.constraints.enumerations.items()
                },
                "opaque_keys": [key for key, _ in self.constraints.opaque],
                "required_request_keys": sorted(self.constraints.required),
                "reasons": list(self.constraints.reasons),
            },
            "budget": (
                None
                if self.budget is None
                else {
                    "readable": self.budget.readable,
                    "remaining_actions": self.budget.remaining_actions,
                    "remaining_amount": self.budget.remaining_amount,
                }
            ),
        }
def bottom_envelope(reason: str) -> AuthorityEnvelope:
    """The envelope that admits nothing.

    Returned whenever the projection cannot be computed. Safe because an
    envelope is never consulted to allow: the worst a spurious bottom can
    do is refuse a request the boundary would have refused anyway once
    Aegis is not consulted at all, and the gate abstains when no grant
    exists.
    """

    return AuthorityEnvelope(reasons=(reason,))


def local_envelope(
    capability: Capability,
    *,
    revoked: bool = False,
    issuer_trusted: Optional[bool] = None,
    depth_ceiling: Optional[int] = None,
    budget: Optional[BudgetBound] = None,
    fingerprint: Optional[str] = None,
) -> AuthorityEnvelope:
    """Project one capability, with no reference to its chain."""

    if not isinstance(capability, Capability):
        return bottom_envelope("not_a_capability")

    issued_at = capability.issued_at
    expires_at = capability.expires_at

    reasons: list[str] = []

    if not _is_finite_number(issued_at):
        reasons.append("issued_at_not_finite")

    if not _is_finite_number(expires_at):
        reasons.append("expires_at_not_finite")

    if reasons:
        # ``CapabilityVerifier.verify`` requires both to be finite numbers
        # and every chain member goes through it, so this is genuinely
        # unusable authority rather than an unhandled shape.
        return AuthorityEnvelope(reasons=tuple(reasons))

    window = (float(issued_at), float(expires_at))

    if window[0] >= window[1]:
        reasons.append("window_inverted")
    tool = capability.tool

    if tool is not None and (not isinstance(tool, str) or not tool.strip()):
        # The verifier refuses a blank or non-string tool binding.
        reasons.append("tool_binding_unusable")

    return AuthorityEnvelope(
        patterns=(capability.capability,),
        tool=tool,
        window=window,
        constraints=local_constraint_bound(capability.constraints),
        depth=1,
        depth_ceiling=depth_ceiling,
        issuers=(capability.issuer,),
        issuer_trusted=issuer_trusted,
        revoked=revoked,
        budget=budget,
        members=(
            fingerprint
            if fingerprint is not None
            else capability_fingerprint(capability),
        ),
        reasons=tuple(reasons),
    )


def meet(
    left: AuthorityEnvelope,
    right: AuthorityEnvelope,
) -> AuthorityEnvelope:
    """The per-dimension meet. ``left`` is the nearer chain member.

    Head-only dimensions (``issuer_trusted``, ``depth_ceiling``) are taken
    from ``left`` rather than combined, because the gates that enforce them
    read the requested capability, not its ancestors. Everything else is a
    genuine meet, which is what makes the result never larger than either
    input.
    """

    reasons = list(left.reasons) + list(right.reasons)

    tools = {value for value in (left.tool, right.tool) if value is not None}

    if len(tools) > 1:
        reasons.append("tool_binding_conflict")

    window = (
        max(left.window[0], right.window[0]),
        min(left.window[1], right.window[1]),
    )

    if window[0] >= window[1]:
        reasons.append("window_empty")
    members = left.members + tuple(
        member for member in right.members if member not in left.members
    )

    return AuthorityEnvelope(
        patterns=left.patterns + tuple(
            pattern for pattern in right.patterns if pattern not in left.patterns
        ),
        tool=next(iter(tools)) if len(tools) == 1 else None,
        window=window,
        constraints=meet_constraint_bounds(left.constraints, right.constraints),
        depth=len(members),
        depth_ceiling=left.depth_ceiling,
        issuers=left.issuers + tuple(
            issuer for issuer in right.issuers if issuer not in left.issuers
        ),
        issuer_trusted=left.issuer_trusted,
        revoked=left.revoked or right.revoked,
        budget=_meet_budget(left.budget, right.budget),
        members=members,
        reasons=tuple(reasons),
    )


def chain_envelope(
    locals_: Sequence[AuthorityEnvelope],
) -> AuthorityEnvelope:
    """Fold a chain's local envelopes, nearest first.

    An empty chain is bottom rather than unbounded. A capability whose
    chain could not be resolved must not be represented as having no
    limits.
    """

    if not locals_:
        return bottom_envelope("empty_chain")

    folded = locals_[0]

    for element in locals_[1:]:
        folded = meet(folded, element)

    return folded
