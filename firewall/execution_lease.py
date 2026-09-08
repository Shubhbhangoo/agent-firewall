"""Execution leases: authority that stays attached to the act.

Why this exists
---------------

v2.6 established that concurrent authority changes cannot widen an
authorization decision, and stated plainly what it does **not** close:
an allow is a verdict about the past. ``authorize()`` returns, the caller
begins acting, and nothing connects the state the verdict rested on to the
moment the action actually executes. Revocation, suspension, expiry and
policy change can all land between ALLOW and the side effect, and the
caller -- and the audit log -- have no record of which one did.

An execution lease is that missing connection. It is a continuation of
one already-made authorization decision, not a second decision:

* It is issued only after the canonical boundary
  (:meth:`firewall.sdk.FirewallSDK.authorize`) has allowed. Nothing in
  this module can grant authority; there is no alternate path to an
  allow, and ``AUTHORIZATION_UNIQUENESS`` keeps it that way.
* It is bound to the material facts of the decision it continues: the
  capability fingerprint, agent, action, request digest, the full
  delegation-chain fingerprint sequence, the policy version, and the
  authority-epoch sample the decision was taken under.
* Execution is admitted through an explicit, recorded state machine --
  ``LEASE_ISSUED -> RESERVED -> STARTED -> COMPLETED`` -- and each
  progression re-establishes the authority basis against live state
  before it happens. That re-establishment is the SDK's job (only the
  SDK may read the security state and decide); the store's job is to
  make the progression an atomic, replay-proof transition. A progression
  whose basis cannot be established is a terminal denial (``DENIED`` /
  ``EXPIRED`` / ``REVOKED``), never a guess.
* The store record is the authority on lease state. A lease *object* is a
  reference the caller carries; it is never trusted for its state, and a
  forged, copied or stale object is refused because the record it names
  does not agree with it or does not exist. ``unknown != trusted``
  applies to leases the same way it applies to capabilities.

What this module is not
-----------------------

It is not a second authorization system. The only allow in the package
still originates in ``firewall/authorization.py::authorize``. The lease
store writes new state but every write narrows or records: issuing a
lease consumes nothing permissive, reserving one consumes it exactly once,
and no value stored here can ever make an ``authorize`` allow.

It is not an evidence recorder and must never become one. The lease
record is *state* -- the authority on what phase an execution is in. The
audit trail of what happened to a capability lives in the lifecycle
recorder and the flight recorder, which already exist. Keeping the two
apart is what lets an operator throw a lease store away without rewriting
history and throw history away without resuming a lease.

The state machine
-----------------

The nine-state vocabulary from the v2.7 design is kept in full
(:class:`ExecutionState`), but records in the store begin at
``LEASE_ISSUED``: ``AUTHORIZED`` is the phase the canonical boundary owns
and records through its own lifecycle ``USED`` event. Transitions are
legal only between the declared edges; every other pair is refused by the
store's compare-and-set, so ``COMPLETED -> STARTED``, ``REVOKED ->
STARTED`` and ``EXPIRED -> STARTED`` cannot be written by any caller,
including one holding the store object.

Concurrency
-----------

Exactly-once belongs to the store, exactly as it belongs to the replay
store's ``PRIMARY KEY``. Every state change is a compare-and-set on the
current state, so two callers racing to reserve one lease produce one
winner and one refusal -- the loser's transition matches no current state.
An optional SQLite backend
(:class:`firewall.execution_store.SQLiteExecutionLeaseStore`) turns the
same CAS into a single ``UPDATE ... WHERE lease_id = ? AND state = ?``,
so the property survives across processes: the guarantee belongs to the
row, not to a per-instance lock.

Non-guarantees are stated in ``docs/v2.7-execution-lease.md``. The one
worth repeating here: the firewall cannot atomically control an external
side effect. Between the ``STARTED`` transition and the moment the
handler's effect lands in the world there is a window no in-process
record can close, exactly as v2.6 documented for the caller acting on an
allow. What v2.7 adds is that the window is now an explicit, recorded
instant, that revocation or suspension arriving *before* it is caught,
and that an execution which loses its authority mid-flight can never be
recorded as a clean ``COMPLETED`` -- it must terminate in an explicit
failure state that says the action ran and the authority did not hold.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

#: Lease lifetime when the caller does not choose one.
DEFAULT_LEASE_TTL_SECONDS = 60.0

#: The nine-phase execution vocabulary. Records stored by
#: :class:`ExecutionLeaseStore` begin at :attr:`LEASE_ISSUED`; the
#: ``AUTHORIZED`` phase is owned by the canonical authorization boundary
#: and is recorded there. All nine exist so that a caller reading an
#: execution record can name the phase it stopped in without translation.
class ExecutionState(str, Enum):
    AUTHORIZED = "authorized"
    LEASE_ISSUED = "lease_issued"
    RESERVED = "reserved"
    STARTED = "started"
    COMPLETED = "completed"
    ABORTED = "aborted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


#: Phases in which an execution can no longer progress or be started.
TERMINAL_STATES = frozenset(
    {
        ExecutionState.COMPLETED,
        ExecutionState.ABORTED,
        ExecutionState.DENIED,
        ExecutionState.EXPIRED,
        ExecutionState.REVOKED,
    }
)

#: The edges of the execution state machine.
#:
#: A key may move only to one of its declared values. Every transition a
#: caller attempts through :meth:`ExecutionLeaseStore.transition` is
#: checked against this table *and* enforced atomically by the store, so
#: an illegal edge is refused even by a caller that skips the check.
#: Terminal states have no outgoing edges, which is what makes
#: ``REVOKED -> STARTED`` and ``EXPIRED -> STARTED`` unrepresentable.
ALLOWED_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    ExecutionState.LEASE_ISSUED: frozenset(
        {
            ExecutionState.RESERVED,
            ExecutionState.DENIED,
            ExecutionState.EXPIRED,
            ExecutionState.REVOKED,
        }
    ),
    ExecutionState.RESERVED: frozenset(
        {
            ExecutionState.STARTED,
            ExecutionState.DENIED,
            ExecutionState.EXPIRED,
            ExecutionState.REVOKED,
            ExecutionState.ABORTED,
        }
    ),
    ExecutionState.STARTED: frozenset(
        {
            ExecutionState.COMPLETED,
            ExecutionState.ABORTED,
            ExecutionState.DENIED,
            ExecutionState.EXPIRED,
            ExecutionState.REVOKED,
        }
    ),
    ExecutionState.AUTHORIZED: frozenset(
        {
            ExecutionState.LEASE_ISSUED,
            ExecutionState.DENIED,
            ExecutionState.EXPIRED,
            ExecutionState.REVOKED,
        }
    ),
}

#: A state with no allowed transitions at all. Nothing may leave these.
TERMINAL_TRANSITION_LIMITS: frozenset[ExecutionState] = frozenset(
    state for state in ExecutionState if state not in ALLOWED_TRANSITIONS
)


def is_terminal(state: Any) -> bool:
    """Whether ``state`` is one of the five terminal execution phases.

    ``AUTHORIZED`` is not terminal -- the whole point of the lease is the
    progression out of it -- but it is also not a state a lease record
    ever stores.
    """

    try:
        return ExecutionState(state) in TERMINAL_STATES
    except (TypeError, ValueError):
        # Not even a phase. Malformed state is not trusted state.
        return True


def transition_allowed(
    current: Any,
    next_state: Any,
) -> bool:
    """Whether the state machine permits ``current -> next_state``.

    Total: any value that is not a phase, or a phase with no declared
    outgoing edge, refuses.
    """

    try:
        current_state = ExecutionState(current)
    except (TypeError, ValueError):
        return False

    try:
        target = ExecutionState(next_state)
    except (TypeError, ValueError):
        return False

    edges = ALLOWED_TRANSITIONS.get(current_state)

    if edges is None:
        return False

    return target in edges


def canonical_request_digest(request: Any) -> str:
    """A stable digest of the request an authorization decided on.

    The lease binds the request through this digest so that a lease
    issued for one request cannot be presented for another. Requests are
    expected to be JSON-shaped (they already passed the constraint
    evaluator); anything that cannot be serialised has no stable digest,
    and the issuance path refuses rather than binding a lease to a value
    it cannot name.
    """

    try:
        payload = json.dumps(
            request if request is not None else {},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "request has no stable digest: "
            f"{type(exc).__name__}"
        ) from exc

    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ExecutionLease:
    """One continuation of one authorization decision.

    The object a caller carries between authorization and execution. Its
    ``state`` field is a convenience projection of the store's record and
    is never trusted by the enforcement path: every operation re-reads
    the authoritative record from the store by ``lease_id`` and compares
    the bound fields (capability fingerprint, agent, action, request
    digest, chain) against this object and against the presented
    capability. A forged object, an object copied from another lease, or
    a stale object therefore disagrees with the record it names and is
    refused.

    ``lease_id`` is a fresh 128-bit random value per issue; ``nonce`` is a
    second independent random value so that a leaked id does not by
    itself reproduce the object. Neither is guessable, and neither is a
    permission -- the record and the live authority state decide.

    ``chain_fingerprints`` is the delegation lineage the decision was
    taken under, leaf first -- the same sequence the chain gate resolves
    from the presented capability. A later progression re-resolves the
    chain and refuses if it no longer matches, so authority cannot be
    detached from an ancestor by rewriting lineage state after the allow.

    ``epoch_finished`` / ``epoch_in_flight`` is the authority-epoch sample
    taken at issue, so that every later progression can ask whether the
    context the decision was taken under still covers this instant. A
    sample is not a permission: its only possible effect is a refusal.
    """

    lease_id: str
    state: ExecutionState
    capability_fingerprint: str
    agent_id: str
    capability: str
    action: str
    request_digest: str
    chain_id: Optional[str]
    policy_version: str
    nonce: str
    issued_at: float
    expires_at: float
    issuer: Optional[str] = None
    tool: Optional[str] = None
    execution_id: Optional[str] = None
    #: The delegation chain, leaf first, as resolved at issue.
    chain_fingerprints: tuple[str, ...] = ()
    #: The authority-epoch sample under which the lease was issued.
    epoch_finished: int = 0
    epoch_in_flight: int = 0
    #: Validation flags recorded at each progression. ``True`` only when
    #: the authority basis was re-established immediately before that
    #: transition; ``None`` before the phase is reached. A record that is
    #: ``COMPLETED`` with any of the three ``False`` would be a lie, and
    #: the EXECUTION_AUTHORITY_CONTINUITY invariant treats exactly that
    #: as a violation.
    reserve_authority_valid: Optional[bool] = None
    start_authority_valid: Optional[bool] = None
    complete_authority_valid: Optional[bool] = None
    #: Whether the external action actually ran. Only meaningful from
    #: ``STARTED`` on; a terminal failure state that follows a started
    #: execution records ``executed=True`` so an operator can tell a
    #: refusal from an interrupted side effect.
    executed: bool = False
    #: Why a terminal state was reached, when one was. Empty while the
    #: record can still progress.
    terminal_reason: str = ""
    #: Per-transition audit trail, most recent last.
    history: tuple[tuple[ExecutionState, ExecutionState, float, str], ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "state": self.state.value,
            "capability_fingerprint": self.capability_fingerprint,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "action": self.action,
            "request_digest": self.request_digest,
            "chain_id": self.chain_id,
            "policy_version": self.policy_version,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "tool": self.tool,
            "execution_id": self.execution_id,
            "chain_fingerprints": list(self.chain_fingerprints),
            "epoch_finished": self.epoch_finished,
            "epoch_in_flight": self.epoch_in_flight,
            "reserve_authority_valid": self.reserve_authority_valid,
            "start_authority_valid": self.start_authority_valid,
            "complete_authority_valid": self.complete_authority_valid,
            "executed": self.executed,
            "terminal_reason": self.terminal_reason,
            "history": [
                {
                    "from": from_state.value,
                    "to": to_state.value,
                    "at": at,
                    "reason": reason,
                }
                for from_state, to_state, at, reason in self.history
            ],
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "ExecutionLease":
        """Reconstruct a lease from its serialized form.

        Reconstruction is deliberately not trust. A lease built here is
        an ordinary object: the enforcement path still requires the store
        to hold a record with this ``lease_id`` and still compares every
        bound field against it. A lease that round-trips through a
        hostile serializer and comes back with ``state="completed"`` is
        refused like any other forged object, because the state the
        enforcement reads is the store's, never this object's.

        Malformed input is refused loudly: a store row that cannot be
        reconstructed is a corrupt row, and the persistent backend
        reports it as such rather than guessing at the missing fields.
        """

        if not isinstance(data, dict):
            raise TypeError("lease data must be a dictionary")

        def _need_str(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"lease field {key!r} must be a non-empty string"
                )
            return value

        def _need_finite(key: str) -> float:
            value = data.get(key)
            if isinstance(value, bool) or not isinstance(
                value, (int, float)
            ):
                raise ValueError(
                    f"lease field {key!r} must be numeric"
                )
            result = float(value)
            if not math.isfinite(result):
                raise ValueError(
                    f"lease field {key!r} must be finite"
                )
            return result

        state_value = data.get("state")
        try:
            state = ExecutionState(state_value)
        except (TypeError, ValueError):
            raise ValueError(
                f"lease field 'state' is not a phase: {state_value!r}"
            ) from None

        chain_fingerprints = data.get("chain_fingerprints", ())
        if isinstance(chain_fingerprints, list):
            chain_fingerprints = tuple(chain_fingerprints)
        if not isinstance(chain_fingerprints, tuple) or not all(
            isinstance(item, str) for item in chain_fingerprints
        ):
            raise ValueError(
                "lease field 'chain_fingerprints' must be a list of "
                "fingerprint strings"
            )

        history_data = data.get("history", [])
        history: list[tuple[ExecutionState, ExecutionState, float, str]] = []
        for item in history_data:
            if not isinstance(item, dict):
                raise ValueError("lease history entries must be objects")
            try:
                from_state = ExecutionState(item["from"])
                to_state = ExecutionState(item["to"])
            except (TypeError, ValueError, KeyError):
                raise ValueError(
                    "lease history holds an unknown phase"
                ) from None
            at = item.get("at")
            if isinstance(at, bool) or not isinstance(at, (int, float)):
                raise ValueError("lease history timestamps must be numeric")
            reason = item.get("reason")
            if not isinstance(reason, str):
                raise ValueError("lease history reasons must be strings")
            history.append(
                (from_state, to_state, float(at), reason)
            )

        return cls(
            lease_id=_need_str("lease_id"),
            state=state,
            capability_fingerprint=_need_str("capability_fingerprint"),
            agent_id=_need_str("agent_id"),
            capability=_need_str("capability"),
            action=_need_str("action"),
            request_digest=_need_str("request_digest"),
            chain_id=data.get("chain_id"),
            policy_version=_need_str("policy_version"),
            nonce=_need_str("nonce"),
            issued_at=_need_finite("issued_at"),
            expires_at=_need_finite("expires_at"),
            issuer=data.get("issuer"),
            tool=data.get("tool"),
            execution_id=data.get("execution_id"),
            chain_fingerprints=chain_fingerprints,
            epoch_finished=int(data.get("epoch_finished", 0) or 0),
            epoch_in_flight=int(data.get("epoch_in_flight", 0) or 0),
            reserve_authority_valid=data.get(
                "reserve_authority_valid"
            ),
            start_authority_valid=data.get(
                "start_authority_valid"
            ),
            complete_authority_valid=data.get(
                "complete_authority_valid"
            ),
            executed=bool(data.get("executed", False)),
            terminal_reason=str(data.get("terminal_reason", "")),
            history=tuple(history),
            details=dict(data.get("details", {}) or {}),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"ExecutionLease(lease_id={self.lease_id[:8]}..., "
            f"state={self.state.value}, "
            f"capability={self.capability!r}, "
            f"agent={self.agent_id!r}, "
            f"action={self.action!r})"
        )


class ExecutionLeaseError(Exception):
    """Base error for the execution lease store."""


class ExecutionIdentityBoundError(ExecutionLeaseError):
    """The execution identity is already attached to another live lease.

    Raised by the store when a caller tries to reserve a second live lease
    against one execution identity. The enforcement path converts it into a
    refused outcome; the type exists so the refusal names its cause without
    parsing an error string.
    """


class IllegalTransitionError(ExecutionLeaseError):
    """A transition the state machine does not permit was attempted."""


@dataclass(frozen=True)
class ExecutionLeaseOutcome:
    """The answer one lease operation returns.

    ``allowed`` is the single bit an executor may act on: it is true only
    when the operation advanced the record to the phase the caller asked
    for (``RESERVED`` for a reservation, ``STARTED`` for a start,
    ``COMPLETED`` for a completion). Every refusal is a verdict-shaped
    ``False`` with a reason, never an exception -- the caller's
    ``except Exception`` must not be what decides what happened to an
    execution, for the same reason v2.5 gave for ``authorize()``.

    ``lease`` is the authoritative record after the attempt, or ``None``
    when the presented lease did not name a record at all.
    """

    allowed: bool
    reason: str
    state: Optional[ExecutionState]
    lease: Optional[ExecutionLease] = None

    @classmethod
    def refused(cls, reason: str) -> "ExecutionLeaseOutcome":
        return cls(allowed=False, reason=reason, state=None, lease=None)


def _lease_id() -> str:
    return uuid.uuid4().hex


def _lease_nonce() -> str:
    return uuid.uuid4().hex


class ExecutionLeaseStore:
    """The authority on execution lease state.

    One lease per ``lease_id``, one binding per ``execution_id`` while
    the execution is live, and every state change is an atomic
    compare-and-set: the record moves only from the state the caller
    claims it is in. Exactly-once for a single-use lease belongs to this
    store, exactly as exactly-once for a nonce belongs to the replay
    store's ``PRIMARY KEY``.

    An optional persistent backend (see
    :class:`firewall.execution_store.SQLiteExecutionLeaseStore`) makes
    records survive a process restart and extends the CAS to a single
    ``UPDATE`` so two processes over one file observe the same
    exactly-once property. Without one, state is held in memory and dies
    with the process -- which is itself a defined crash outcome: a lease
    that no longer exists cannot authorise anything, and no record is
    left behind claiming a completion that never happened.

    The store decides *phase*, never *permission*. It has no reference
    to any authority store and constructs no verdict. The SDK -- and
    only the SDK -- decides whether an authority basis still holds and
    then asks the store to make the corresponding phase change atomic.
    """

    def __init__(
        self,
        *,
        clock=None,
        backend: Optional[Any] = None,
    ):
        self._clock = clock if clock is not None else time.time
        self._backend = backend
        self._lock = threading.RLock()
        self._records: dict[str, ExecutionLease] = {}
        #: ``execution_id -> lease_id`` while the binding is live.
        self._bindings: dict[str, str] = {}

        if backend is not None:
            for record in backend.load():
                self._records[record.lease_id] = record
                if (
                    record.execution_id is not None
                    and not is_terminal(record.state)
                ):
                    self._bindings[record.execution_id] = record.lease_id

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise ExecutionLeaseError(
                "execution lease clock could not be read"
            ) from None

    def now(self) -> float:
        """The store's own reading of the clock its deadlines use.

        Public so the enforcement path can compare a lease's deadline in
        the same time base the store stamps it in. An unreadable clock is
        an :class:`ExecutionLeaseError`; the enforcement path turns that
        into a refusal, never into a pass.
        """

        return self._now()

    # ========================================================
    # Issue
    # ========================================================

    def issue(
        self,
        *,
        capability_fingerprint: str,
        agent_id: str,
        capability: str,
        action: str,
        request_digest: str,
        chain_id: Optional[str],
        policy_version: str,
        ttl: float,
        issuer: Optional[str] = None,
        tool: Optional[str] = None,
        chain_fingerprints: tuple[str, ...] = (),
        epoch_finished: int = 0,
        epoch_in_flight: int = 0,
    ) -> ExecutionLease:
        """Create a lease in ``LEASE_ISSUED``.

        The caller (the SDK, and only the SDK) has already obtained a
        canonical allow for exactly these facts. Nothing in this method
        re-decides that; it records the continuation.

        Raises :class:`ExecutionLeaseError` when the lease cannot be
        recorded, so the caller can withhold the allow it cannot attach
        an execution to.
        """

        for label, value in (
            ("capability_fingerprint", capability_fingerprint),
            ("agent_id", agent_id),
            ("capability", capability),
            ("action", action),
            ("request_digest", request_digest),
            ("policy_version", policy_version),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be a non-empty string")

        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool):
            raise TypeError("ttl must be numeric")

        ttl = float(ttl)

        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl must be a finite positive number")

        if chain_id is not None and (
            not isinstance(chain_id, str) or not chain_id
        ):
            raise ValueError("chain_id must be a non-empty string or None")

        if not isinstance(chain_fingerprints, tuple) or not all(
            isinstance(item, str) for item in chain_fingerprints
        ):
            raise ValueError(
                "chain_fingerprints must be a tuple of fingerprint strings"
            )

        if isinstance(epoch_finished, bool) or not isinstance(
            epoch_finished, int
        ):
            raise TypeError("epoch_finished must be an integer")

        if isinstance(epoch_in_flight, bool) or not isinstance(
            epoch_in_flight, int
        ):
            raise TypeError("epoch_in_flight must be an integer")

        if epoch_finished < 0 or epoch_in_flight < 0:
            raise ValueError("epoch counts cannot be negative")

        issued_at = self._now()
        expires_at = issued_at + ttl

        record = ExecutionLease(
            lease_id=_lease_id(),
            state=ExecutionState.LEASE_ISSUED,
            capability_fingerprint=capability_fingerprint,
            agent_id=agent_id,
            capability=capability,
            action=action,
            request_digest=request_digest,
            chain_id=chain_id,
            policy_version=policy_version,
            nonce=_lease_nonce(),
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=issuer,
            tool=tool,
            chain_fingerprints=chain_fingerprints,
            epoch_finished=epoch_finished,
            epoch_in_flight=epoch_in_flight,
            history=(
                (
                    ExecutionState.AUTHORIZED,
                    ExecutionState.LEASE_ISSUED,
                    issued_at,
                    "",
                ),
            ),
        )

        with self._lock:
            if record.lease_id in self._records:
                # Collision on a 128-bit random id is not a thing that
                # happens; a store that reports it is refusing to lie.
                raise ExecutionLeaseError(
                    "lease id collision on issue"
                )

            self._write_backend_issue(record)
            self._records[record.lease_id] = record

        return record

    # ========================================================
    # Lookup
    # ========================================================

    def get(
        self,
        lease_id: str,
    ) -> Optional[ExecutionLease]:
        """The authoritative record for ``lease_id``, or ``None``.

        ``None`` is the fail-closed answer: an unknown lease cannot
        authorise anything. It is never treated as an absent record that
        can be recreated.
        """

        if not isinstance(lease_id, str) or not lease_id:
            return None

        with self._lock:
            return self._records.get(lease_id)

    def records(self) -> tuple[ExecutionLease, ...]:
        """Every lease the store holds, in insertion order."""

        with self._lock:
            return tuple(self._records.values())

    def active_execution_ids(self) -> tuple[str, ...]:
        """Execution identities currently bound to a live lease."""

        with self._lock:
            return tuple(sorted(self._bindings))

    # ========================================================
    # Transitions
    # ========================================================

    def transition(
        self,
        lease_id: str,
        next_state: ExecutionState,
        *,
        execution_id: Optional[str] = None,
        reserve_authority_valid: Optional[bool] = None,
        start_authority_valid: Optional[bool] = None,
        complete_authority_valid: Optional[bool] = None,
        executed: Optional[bool] = None,
        terminal_reason: str = "",
        reason: str = "",
        details: Optional[dict[str, Any]] = None,
    ) -> Optional[ExecutionLease]:
        """Atomically move a record from its current state to ``next_state``.

        Returns the new record on success and ``None`` when the record is
        absent or is not in the state the transition expects -- the
        compare-and-set failed. ``None`` is never retried into success by
        the caller; it is a refusal (a replayed reservation, a lease that
        already moved).

        The state machine table is checked first, and the CAS is the
        enforcement: even a caller that checked nothing cannot move
        ``COMPLETED -> STARTED`` because the record is not in
        ``COMPLETED``'s edge set and the store refuses it.

        ``execution_id`` binds the lease to one execution identity. The
        binding is exclusive while the lease is live: two different live
        leases naming one execution identity is refused (the identity
        would name two in-flight executions), and a lease that reaches a
        terminal state releases its identity so a later execution may
        reuse the label.

        Raises :class:`IllegalTransitionError` for an edge the state
        machine does not declare and :class:`ExecutionLeaseError` when
        the identity is bound to another lease or the backend refuses
        the write.
        """

        with self._lock:
            record = self._records.get(lease_id)

            if record is None:
                return None

            if not transition_allowed(record.state, next_state):
                raise IllegalTransitionError(
                    f"{record.state.value} -> {next_state.value} is not "
                    "a legal execution transition"
                )

            at = self._now()

            next_record = replace(
                record,
                state=next_state,
                execution_id=(
                    execution_id
                    if execution_id is not None
                    else record.execution_id
                ),
                reserve_authority_valid=(
                    reserve_authority_valid
                    if reserve_authority_valid is not None
                    else record.reserve_authority_valid
                ),
                start_authority_valid=(
                    start_authority_valid
                    if start_authority_valid is not None
                    else record.start_authority_valid
                ),
                complete_authority_valid=(
                    complete_authority_valid
                    if complete_authority_valid is not None
                    else record.complete_authority_valid
                ),
                executed=(
                    executed if executed is not None else record.executed
                ),
                terminal_reason=(
                    terminal_reason
                    if terminal_reason
                    else record.terminal_reason
                ),
                history=record.history
                + (
                    (
                        record.state,
                        next_state,
                        at,
                        reason,
                    ),
                ),
                details=(
                    dict(details)
                    if details is not None
                    else record.details
                ),
            )

            if is_terminal(next_state) and not next_record.terminal_reason:
                next_record = replace(
                    next_record,
                    terminal_reason=reason or next_state.value,
                )

            # An execution identity may only be attached to one live
            # lease. Checked in memory first (the single-process case);
            # the backend re-checks it through its unique index when one
            # is present (the cross-process case).
            if not is_terminal(next_state):
                if next_record.execution_id is not None:
                    existing = self._bindings.get(
                        next_record.execution_id
                    )

                    if (
                        existing is not None
                        and existing != lease_id
                    ):
                        raise ExecutionIdentityBoundError(
                            "execution identity is bound to another lease"
                        )

            # Persist before publishing in memory so a failed write never
            # leaves an in-memory state the backend does not hold.
            self._write_backend_transition(record, next_record)

            self._records[lease_id] = next_record

            # Release or refresh the execution-identity binding. A lease
            # that reaches a terminal state stops occupying its execution
            # identity, so a later lease may reuse the identity -- an
            # execution identity is a label for one *live* execution, and
            # reusing a finished one is not a replay of a running one.
            if is_terminal(next_state):
                if record.execution_id is not None:
                    self._bindings.pop(record.execution_id, None)
            else:
                if (
                    record.execution_id is not None
                    and record.execution_id != next_record.execution_id
                ):
                    self._bindings.pop(record.execution_id, None)

                if next_record.execution_id is not None:
                    self._bindings[next_record.execution_id] = lease_id

            return next_record

    def expire_lapsed(self) -> int:
        """Terminate leases whose deadline has passed without progression.

        Only non-terminal records may lapse. A ``STARTED`` record whose
        deadline passed mid-flight is *not* touched: the action may
        genuinely be running, and deciding it did not is exactly the kind
        of guess this store refuses to make. It stays ``STARTED`` -- not
        ``COMPLETED`` -- until the caller finishes or aborts it.
        """

        now = self._now()
        changed = 0

        with self._lock:
            for lease_id, record in list(self._records.items()):
                if is_terminal(record.state):
                    continue

                if record.state is ExecutionState.STARTED:
                    continue

                if record.expires_at > now:
                    continue

                try:
                    self.transition(
                        lease_id,
                        ExecutionState.EXPIRED,
                        reason="lease_deadline_passed",
                        terminal_reason="lease_deadline_passed",
                    )
                except _CasRefused:
                    # Another process moved this lease between our read
                    # and our write; it is no longer ours to lapse.
                    continue
                changed += 1

        return changed

    # ========================================================
    # Backend persistence
    # ========================================================

    def _write_backend_issue(
        self,
        record: ExecutionLease,
    ) -> None:
        if self._backend is None:
            return
        self._backend.insert(record)

    def _write_backend_transition(
        self,
        previous: ExecutionLease,
        record: ExecutionLease,
    ) -> None:
        if self._backend is None:
            return

        moved = self._backend.cas(
            previous.lease_id,
            previous.state,
            record,
        )

        if not moved:
            # Another process advanced this row between our read and our
            # write. Our in-memory copy is stale; refresh it from the
            # backend so the next operation sees the current phase, and
            # report the CAS failure to the caller as a refusal.
            self._refresh_from_backend(previous.lease_id)
            raise _CasRefused(
                previous.lease_id,
                previous.state,
            )

    def _refresh_from_backend(
        self,
        lease_id: str,
    ) -> None:
        if self._backend is None:
            return

        try:
            current = self._backend.load_one(lease_id)
        except Exception:  # noqa: BLE001 - refresh is best effort
            current = None

        if current is None:
            self._records.pop(lease_id, None)
            return

        previous = self._records.get(lease_id)
        if (
            previous is not None
            and previous.execution_id is not None
            and previous.execution_id != current.execution_id
        ):
            self._bindings.pop(previous.execution_id, None)

        self._records[lease_id] = current

        if (
            current.execution_id is not None
            and not is_terminal(current.state)
        ):
            self._bindings[current.execution_id] = lease_id

    # ========================================================
    # Inspection
    # ========================================================

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

    def __enter__(self) -> "ExecutionLeaseStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class _CasRefused(ExecutionLeaseError):
    """Internal: the backend's compare-and-set matched no row.

    Converted by the enforcement path into a refused outcome. Not part of
    the public vocabulary -- callers see ``ExecutionLeaseOutcome``.
    """

    def __init__(self, lease_id: str, expected: ExecutionState):
        super().__init__(
            f"lease {lease_id[:8]}... is no longer in "
            f"{expected.value}; the transition was refused"
        )
        self.lease_id = lease_id
        self.expected = expected


__all__ = [
    "ALLOWED_TRANSITIONS",
    "DEFAULT_LEASE_TTL_SECONDS",
    "ExecutionLease",
    "ExecutionLeaseError",
    "ExecutionIdentityBoundError",
    "ExecutionLeaseOutcome",
    "ExecutionLeaseStore",
    "ExecutionState",
    "IllegalTransitionError",
    "TERMINAL_STATES",
    "TERMINAL_TRANSITION_LIMITS",
    "canonical_request_digest",
    "is_terminal",
    "transition_allowed",
]
