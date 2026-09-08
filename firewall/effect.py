"""Side-effect journal: an explicit, attestable, idempotent, recoverable
record of one external side effect belonging to one execution lease.

v2.7 recorded the continuation of an allow -- ``AUTHORIZED ->
LEASE_ISSUED -> RESERVED -> STARTED -> COMPLETED`` -- and stated plainly
where its guarantee stops. Between the ``STARTED`` transition and the
moment the handler's effect lands in the world there is a window no
in-process record can close: the firewall does not own the external
system, cannot roll an effect back, and "a lease does not make an action
idempotent".

v2.8 does not claim to close that window. It makes the implicit boundary
**explicit, attestable, idempotent and recoverable**, so that Agent
Firewall's own representation of a side effect never claims more
certainty, authority or completion than the protocol actually
established:

* **Intent durability (outbox).** The intended external effect is
  recorded durably (``INTENT_RECORDED``) *before* any external request
  can be authorized, so a crash never leaves the world changed and the
  firewall with no memory of what it intended.
* **A recorded attempt.** The boundary crossing is one atomic transition
  to ``ATTEMPT_STARTED``. After it the journal says an attempt was
  authorized and initiated; it does *not* say what happened.
* **A three-way outcome.** An attempt resolves to ``SUCCEEDED``,
  ``FAILED`` or ``UNKNOWN``. ``UNKNOWN != SUCCESS`` and
  ``UNKNOWN != FAILURE``: a timeout after transmission is never
  automatically recorded as either.
* **Receipts are observations, not authority.** A receipt records what
  the external handler *claimed* happened, who claimed it
  (``caller_assertion`` / ``handler_observation`` /
  ``provider_evidence``), and any external correlation id, as evidence.
  ``receipt != proof`` unless the integration authenticates the provider.
* **Idempotent retries.** One lease may carry exactly one side-effect
  row keyed by ``(lease_id, idempotency_key)``; repeating the same
  logical effect with the same key returns the same row and cannot
  authorize a second attempt.
* **Recovery by reconciliation.** An effect stuck in ``ATTEMPT_STARTED``
  (crash after transmission, timeout) is resolved only by an explicit
  reconciliation recording confirmed success, confirmed failure, or
  *still unknown* -- never by an automatic retry that could duplicate a
  real-world action.

The journal is **state, not evidence and not authority**, exactly like
the lease store. It is a second journal beside the lease journal: an
operator may throw it away without rewriting history and archive history
without resuming a side effect. Nothing here can make an ``authorize``
allow.

What this module is not
-----------------------

It is not a second authorization system. The only allow in the package
still originates in ``firewall/authorization.py::authorize`` and the
only continuation of one is an execution lease. Every journal
progression is preceded by the SDK re-establishing the *lease* authority
basis against live state -- the same deny-only continuity validation
v2.7 runs on the lease itself -- so a journal row can never advance
under authority the execution cannot still establish. The journal has no
reference to any authority store and constructs no verdict.

It is not a workflow engine and not a general outbox for arbitrary
application messages. It models exactly one shape: one authorized
external effect per execution, where the effect is the handler's
real-world action the firewall cannot roll back.

The state machine
-----------------

::

    INTENT_RECORDED --attempt--> ATTEMPT_STARTED --receipt/--> SUCCEEDED
         |     (nothing transmitted)              reconcile    FAILED
         |                                                       UNKNOWN
         +-- FAILED (confirmed before transmission)              ^
                                                       UNKNOWN --+-- reconcile
                                                                 (SUCCEEDED/FAILED/
                                                                  UNKNOWN re-stamp)

``SUCCEEDED`` and ``FAILED`` are terminal: no transition leaves them, so
a replayed receipt cannot produce a second completion and a confirmed
outcome is never silently rewritten. ``UNKNOWN`` is not terminal in the
state-machine sense -- an explicit reconciliation may resolve it -- but
it is never auto-retried: the only way out of ``UNKNOWN`` is an
evidence-carrying reconciliation.

Concurrency
-----------

Exactly-once belongs to the store. One lease may carry one row (unique
constraint on ``lease_id``); an attempt is one compare-and-set
``INTENT_RECORDED -> ATTEMPT_STARTED``; a receipt/reconciliation is one
compare-and-set from the current state. The optional SQLite backend
(:class:`firewall.effect_store.SQLiteEffectJournal`) turns each CAS into
one ``UPDATE ... WHERE effect_id = ? AND state = ?`` so the property
survives across processes -- the row decides, not a per-instance lock.

Non-guarantees are stated in ``docs/v2.8-side-effect-commit.md``: none
of this makes the external world transactional. If the external system
already executed the request and the firewall only ever sees a timeout,
the effect is recorded ``UNKNOWN`` and stays unknown until an
external-status query or an operator reconciles it. Agent Firewall can
guarantee what its own record claims; it cannot guarantee what an
uncontrolled external system did.
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

#: How long a prepared effect may wait before its attempt must begin. Only
#: ``INTENT_RECORDED`` rows lapse; an attempted effect stays for
#: reconciliation instead of expiring into a guess.
DEFAULT_EFFECT_TTL_SECONDS = 60.0


class EffectState(str, Enum):
    """The recorded phase of one external side effect."""

    INTENT_RECORDED = "intent_recorded"
    ATTEMPT_STARTED = "attempt_started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


#: Confirmed terminal outcomes. ``UNKNOWN`` is deliberately absent: an
#: explicit, evidence-carrying reconciliation may resolve it. What it is
#: terminal *for* is automatic progress -- nothing may auto-retry it.
TERMINAL_EFFECT_STATES = frozenset(
    {EffectState.SUCCEEDED, EffectState.FAILED}
)

#: The edges of the side-effect state machine.
ALLOWED_EFFECT_TRANSITIONS: dict[EffectState, frozenset[EffectState]] = {
    EffectState.INTENT_RECORDED: frozenset(
        {EffectState.ATTEMPT_STARTED, EffectState.FAILED}
    ),
    EffectState.ATTEMPT_STARTED: frozenset(
        {EffectState.SUCCEEDED, EffectState.FAILED, EffectState.UNKNOWN}
    ),
    EffectState.UNKNOWN: frozenset(
        {
            EffectState.SUCCEEDED,
            EffectState.FAILED,
            # Reconcile that still cannot establish an outcome re-stamps
            # UNKNOWN (recorded in history) rather than dropping the
            # reconciliation attempt.
            EffectState.UNKNOWN,
        }
    ),
}


def is_terminal_effect(state: Any) -> bool:
    """Whether ``state`` is a confirmed terminal side-effect outcome.

    Malformed state is not trusted state, so anything that is not a
    declared phase answers as terminal -- the journal must not advance it.
    """

    try:
        return EffectState(state) in TERMINAL_EFFECT_STATES
    except (TypeError, ValueError):
        return True


def effect_transition_allowed(current: Any, next_state: Any) -> bool:
    """Whether the side-effect machine permits ``current -> next_state``.

    Total: unknown or undeclared values refuse. ``UNKNOWN -> UNKNOWN`` is
    the one legal self-edge, reserved for reconciliation attempts that
    still cannot establish an outcome.
    """

    try:
        current_state = EffectState(current)
    except (TypeError, ValueError):
        return False
    try:
        target = EffectState(next_state)
    except (TypeError, ValueError):
        return False
    edges = ALLOWED_EFFECT_TRANSITIONS.get(current_state)
    if edges is None:
        return False
    return target in edges


def canonical_effect_digest(effect: Any) -> str:
    """A stable digest of an intended external effect.

    The journal binds the effect through this digest so that a modified
    effect can never silently execute under a recorded intent: a
    presented effect whose digest disagrees with the bound one is refused
    as ``effect_mismatch`` before anything advances. Effects are expected
    to be JSON-shaped; anything unserialisable has no stable digest and
    the caller is refused rather than bound to a value it cannot name.
    """

    try:
        payload = json.dumps(
            effect if effect is not None else {},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"effect has no stable digest: {type(exc).__name__}"
        ) from exc

    return hashlib.sha256(payload).hexdigest()


class EffectOutcome(str, Enum):
    """The three-way result a handler claims to have observed.

    ``UNKNOWN != SUCCEEDED`` and ``UNKNOWN != FAILED``. A timeout after a
    request was transmitted is UNKNOWN -- the external system may have
    processed it -- and must not be recorded as either a clean success or
    a confirmed failure without further evidence.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ReceiptKind(str, Enum):
    """Who supplied a receipt, and therefore what it may claim.

    A receipt is an observation, never a permission. Caller assertions,
    handler observations and authenticated provider evidence carry very
    different weight and stay distinct in the data model. Only an
    integration that actually authenticates the provider response may
    label evidence ``provider_evidence``.
    """

    CALLER_ASSERTION = "caller_assertion"
    HANDLER_OBSERVATION = "handler_observation"
    PROVIDER_EVIDENCE = "provider_evidence"


@dataclass(frozen=True)
class SideEffectRecord:
    """The authoritative record of one external side effect.

    The object a caller carries between protocol steps is a reference;
    the journal row is the authority on its state, exactly as a lease
    object is a reference to its lease-store record. A forged, copied or
    edited record is refused because it disagrees with the row it names.

    The binding fields (capability fingerprint, agent, capability,
    action, request digest, effect type/digest, chain, policy version,
    epoch sample, idempotency key) are fixed at creation and never move;
    the lifecycle fields below them are the only things a transition may
    change.
    """

    effect_id: str
    lease_id: str
    execution_id: Optional[str]
    capability_fingerprint: str
    agent_id: str
    capability: str
    action: str
    request_digest: str
    effect_type: str
    effect_digest: str
    idempotency_key: str
    chain_id: Optional[str]
    policy_version: str
    issuer: Optional[str]
    tool: Optional[str]
    chain_fingerprints: tuple[str, ...] = ()
    epoch_finished: int = 0
    epoch_in_flight: int = 0
    state: EffectState = EffectState.INTENT_RECORDED
    created_at: float = 0.0
    expires_at: float = 0.0
    attempt_id: Optional[str] = None
    attempted_at: Optional[float] = None
    observed_outcome: Optional[EffectOutcome] = None
    observed_at: Optional[float] = None
    evidence_kind: Optional[ReceiptKind] = None
    #: External correlation evidence (request/transaction id), preserved
    #: when the handler supplies one. Correlation evidence is not proof.
    external_request_id: Optional[str] = None
    provider: Optional[str] = None
    note: Optional[str] = None
    #: True only when the execution's authority basis was re-established
    #: immediately before that transition; ``False`` records an observed
    #: outcome that arrived after authority was lost (the effect may still
    #: have happened -- the record says so -- but it did not complete
    #: under currently valid authority).
    intent_authority_valid: Optional[bool] = None
    attempt_authority_valid: Optional[bool] = None
    receipt_authority_valid: Optional[bool] = None
    reconcile_count: int = 0
    last_reconciled_at: Optional[float] = None
    terminal_reason: str = ""
    history: tuple[tuple[EffectState, EffectState, float, str], ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "lease_id": self.lease_id,
            "execution_id": self.execution_id,
            "capability_fingerprint": self.capability_fingerprint,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "action": self.action,
            "request_digest": self.request_digest,
            "effect_type": self.effect_type,
            "effect_digest": self.effect_digest,
            "idempotency_key": self.idempotency_key,
            "chain_id": self.chain_id,
            "policy_version": self.policy_version,
            "issuer": self.issuer,
            "tool": self.tool,
            "chain_fingerprints": list(self.chain_fingerprints),
            "epoch_finished": self.epoch_finished,
            "epoch_in_flight": self.epoch_in_flight,
            "state": self.state.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "attempt_id": self.attempt_id,
            "attempted_at": self.attempted_at,
            "observed_outcome": (
                self.observed_outcome.value
                if self.observed_outcome is not None
                else None
            ),
            "observed_at": self.observed_at,
            "evidence_kind": (
                self.evidence_kind.value
                if self.evidence_kind is not None
                else None
            ),
            "external_request_id": self.external_request_id,
            "provider": self.provider,
            "note": self.note,
            "intent_authority_valid": self.intent_authority_valid,
            "attempt_authority_valid": self.attempt_authority_valid,
            "receipt_authority_valid": self.receipt_authority_valid,
            "reconcile_count": self.reconcile_count,
            "last_reconciled_at": self.last_reconciled_at,
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
    def from_dict(cls, data: Any) -> "SideEffectRecord":
        """Reconstruct a record from its serialized form.

        Reconstruction is deliberately not trust, exactly as lease
        reconstruction is not trust: the enforcement path still requires
        the journal to hold a row for this ``effect_id`` and still
        compares every bound field against it. Malformed input is refused
        loudly -- a store row that cannot be reconstructed is a corrupt
        row.
        """

        if not isinstance(data, dict):
            raise TypeError("side-effect record data must be a dictionary")

        def _need_str(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"side-effect field {key!r} must be a non-empty string"
                )
            return value

        def _finite(key: str) -> float:
            value = data.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"side-effect field {key!r} must be numeric"
                )
            result = float(value)
            if not math.isfinite(result):
                raise ValueError(f"side-effect field {key!r} must be finite")
            return result

        def _opt_str(key: str) -> Optional[str]:
            value = data.get(key)
            if value is None:
                return None
            if not isinstance(value, str):
                raise ValueError(
                    f"side-effect field {key!r} must be a string or None"
                )
            return value

        def _opt_finite(key: str) -> Optional[float]:
            value = data.get(key)
            if value is None:
                return None
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"side-effect field {key!r} must be numeric or None"
                )
            result = float(value)
            if not math.isfinite(result):
                raise ValueError(
                    f"side-effect field {key!r} must be finite"
                )
            return result

        try:
            state = EffectState(data.get("state"))
        except (TypeError, ValueError):
            raise ValueError(
                f"side-effect field 'state' is not a phase: {data.get('state')!r}"
            ) from None

        observed_value = data.get("observed_outcome")
        try:
            observed_outcome = (
                EffectOutcome(observed_value)
                if observed_value is not None
                else None
            )
        except (TypeError, ValueError):
            raise ValueError(
                "side-effect field 'observed_outcome' is not an outcome: "
                f"{observed_value!r}"
            ) from None

        evidence_value = data.get("evidence_kind")
        try:
            evidence_kind = (
                ReceiptKind(evidence_value)
                if evidence_value is not None
                else None
            )
        except (TypeError, ValueError):
            raise ValueError(
                "side-effect field 'evidence_kind' is not a receipt kind: "
                f"{evidence_value!r}"
            ) from None

        chain_fingerprints = data.get("chain_fingerprints", ())
        if isinstance(chain_fingerprints, list):
            chain_fingerprints = tuple(chain_fingerprints)
        if not isinstance(chain_fingerprints, tuple) or not all(
            isinstance(item, str) for item in chain_fingerprints
        ):
            raise ValueError(
                "side-effect field 'chain_fingerprints' must be a list of "
                "fingerprint strings"
            )

        history: list[tuple[EffectState, EffectState, float, str]] = []
        for item in data.get("history", []):
            if not isinstance(item, dict):
                raise ValueError("side-effect history entries must be objects")
            try:
                from_state = EffectState(item["from"])
                to_state = EffectState(item["to"])
            except (TypeError, ValueError, KeyError):
                raise ValueError(
                    "side-effect history holds an unknown phase"
                ) from None
            at = item.get("at")
            if isinstance(at, bool) or not isinstance(at, (int, float)):
                raise ValueError(
                    "side-effect history timestamps must be numeric"
                )
            reason = item.get("reason")
            if not isinstance(reason, str):
                raise ValueError("side-effect history reasons must be strings")
            history.append((from_state, to_state, float(at), reason))

        return cls(
            effect_id=_need_str("effect_id"),
            lease_id=_need_str("lease_id"),
            execution_id=data.get("execution_id"),
            capability_fingerprint=_need_str("capability_fingerprint"),
            agent_id=_need_str("agent_id"),
            capability=_need_str("capability"),
            action=_need_str("action"),
            request_digest=_need_str("request_digest"),
            effect_type=_need_str("effect_type"),
            effect_digest=_need_str("effect_digest"),
            idempotency_key=_need_str("idempotency_key"),
            chain_id=data.get("chain_id"),
            policy_version=_need_str("policy_version"),
            issuer=data.get("issuer"),
            tool=data.get("tool"),
            chain_fingerprints=chain_fingerprints,
            epoch_finished=int(data.get("epoch_finished", 0) or 0),
            epoch_in_flight=int(data.get("epoch_in_flight", 0) or 0),
            state=state,
            created_at=_finite("created_at"),
            expires_at=_finite("expires_at"),
            attempt_id=_opt_str("attempt_id"),
            attempted_at=_opt_finite("attempted_at"),
            observed_outcome=observed_outcome,
            observed_at=_opt_finite("observed_at"),
            evidence_kind=evidence_kind,
            external_request_id=_opt_str("external_request_id"),
            provider=_opt_str("provider"),
            note=_opt_str("note"),
            intent_authority_valid=data.get("intent_authority_valid"),
            attempt_authority_valid=data.get("attempt_authority_valid"),
            receipt_authority_valid=data.get("receipt_authority_valid"),
            reconcile_count=int(data.get("reconcile_count", 0) or 0),
            last_reconciled_at=_opt_finite("last_reconciled_at"),
            terminal_reason=str(data.get("terminal_reason", "")),
            history=tuple(history),
            details=dict(data.get("details", {}) or {}),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"SideEffectRecord(effect_id={self.effect_id[:8]}..., "
            f"state={self.state.value}, effect_type={self.effect_type!r})"
        )


class EffectJournalError(Exception):
    """Base error for the side-effect journal."""


class IllegalEffectTransitionError(EffectJournalError):
    """A transition the side-effect machine does not permit was attempted."""


class EffectAlreadyBoundError(EffectJournalError):
    """The lease already carries a side-effect row.

    One execution lease may carry exactly one side effect. A second
    ``create`` for the same lease is refused at the store; the
    enforcement path serves an idempotent retry from the existing row or
    refuses a modified effect.
    """


@dataclass(frozen=True)
class EffectResult:
    """The answer one side-effect protocol operation returns.

    ``allowed`` is the single bit a caller may act on: true only when the
    operation actually recorded the state the caller asked for (the
    intent, the attempt, or the resolution). Every refusal is a
    verdict-shaped ``False`` with a reason -- never an exception -- so a
    caller's ``except Exception`` is never what decides what happened to
    an external effect.

    ``effect`` is the authoritative journal record after the attempt, or
    ``None`` when the presented record did not name a row at all.
    """

    allowed: bool
    reason: str
    state: Optional[EffectState]
    effect: Optional[SideEffectRecord] = None

    @classmethod
    def refused(cls, reason: str) -> "EffectResult":
        return cls(allowed=False, reason=reason, state=None, effect=None)


def _effect_id() -> str:
    return uuid.uuid4().hex


class EffectJournal:
    """The authority on side-effect journal state.

    One row per lease, one attempt per row, and every state change is an
    atomic compare-and-set. The store decides *phase*, never *permission*:
    it has no reference to any authority store and constructs no verdict.
    The SDK -- and only the SDK -- decides whether the execution's
    authority basis still holds and then asks the store to make the phase
    change atomic.

    An optional persistent backend (see
    :class:`firewall.effect_store.SQLiteEffectJournal`) makes rows survive
    a process restart and extends the CAS to a single ``UPDATE``.
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
        self._records: dict[str, SideEffectRecord] = {}
        self._by_lease: dict[str, str] = {}

        if backend is not None:
            for record in backend.load():
                self._records[record.effect_id] = record
                self._by_lease[record.lease_id] = record.effect_id

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise EffectJournalError(
                "side-effect journal clock could not be read"
            ) from None

    def now(self) -> float:
        """The journal's own clock reading, for deadline comparison."""

        return self._now()

    # ========================================================
    # Create (durable intent)
    # ========================================================

    def create(
        self,
        *,
        lease_id: str,
        execution_id: Optional[str],
        capability_fingerprint: str,
        agent_id: str,
        capability: str,
        action: str,
        request_digest: str,
        effect_type: str,
        effect_digest: str,
        idempotency_key: str,
        chain_id: Optional[str],
        policy_version: str,
        issuer: Optional[str] = None,
        tool: Optional[str] = None,
        chain_fingerprints: tuple[str, ...] = (),
        epoch_finished: int = 0,
        epoch_in_flight: int = 0,
        ttl: float = DEFAULT_EFFECT_TTL_SECONDS,
        intent_authority_valid: Optional[bool] = None,
    ) -> SideEffectRecord:
        """Create the durable intent row in ``INTENT_RECORDED``.

        The caller (the SDK, and only the SDK) has already established
        that the lease is live and its authority basis holds. Nothing here
        re-decides that; it records the durable intent that must exist
        *before* any external request can be authorized.

        Raises :class:`EffectAlreadyBoundError` when this lease already
        carries a row (so the enforcement path can serve an idempotent
        retry from the existing row or refuse a modified effect) and
        :class:`EffectJournalError` when the row cannot be persisted --
        an intent must not be reported durable when the journal could not
        write it.
        """

        for label, value in (
            ("lease_id", lease_id),
            ("capability_fingerprint", capability_fingerprint),
            ("agent_id", agent_id),
            ("capability", capability),
            ("action", action),
            ("request_digest", request_digest),
            ("effect_type", effect_type),
            ("effect_digest", effect_digest),
            ("idempotency_key", idempotency_key),
            ("policy_version", policy_version),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be a non-empty string")

        if execution_id is not None and (
            not isinstance(execution_id, str) or not execution_id
        ):
            raise ValueError(
                "execution_id must be a non-empty string or None"
            )

        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            raise TypeError("ttl must be numeric")
        ttl = float(ttl)
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl must be a finite positive number")

        if not isinstance(chain_fingerprints, tuple) or not all(
            isinstance(item, str) for item in chain_fingerprints
        ):
            raise ValueError(
                "chain_fingerprints must be a tuple of fingerprint strings"
            )

        for label, value in (
            ("epoch_finished", epoch_finished),
            ("epoch_in_flight", epoch_in_flight),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} cannot be negative")

        created_at = self._now()
        expires_at = created_at + ttl

        record = SideEffectRecord(
            effect_id=_effect_id(),
            lease_id=lease_id,
            execution_id=execution_id,
            capability_fingerprint=capability_fingerprint,
            agent_id=agent_id,
            capability=capability,
            action=action,
            request_digest=request_digest,
            effect_type=effect_type,
            effect_digest=effect_digest,
            idempotency_key=idempotency_key,
            chain_id=chain_id,
            policy_version=policy_version,
            issuer=issuer,
            tool=tool,
            chain_fingerprints=chain_fingerprints,
            epoch_finished=epoch_finished,
            epoch_in_flight=epoch_in_flight,
            state=EffectState.INTENT_RECORDED,
            created_at=created_at,
            expires_at=expires_at,
            intent_authority_valid=intent_authority_valid,
        )

        with self._lock:
            if record.lease_id in self._by_lease:
                raise EffectAlreadyBoundError(
                    "lease already carries a side-effect row"
                )

            self._write_backend_create(record)
            self._records[record.effect_id] = record
            self._by_lease[record.lease_id] = record.effect_id

        return record

    # ========================================================
    # Lookup
    # ========================================================

    def get(self, effect_id: str) -> Optional[SideEffectRecord]:
        """The authoritative row for ``effect_id``, or ``None``."""

        if not isinstance(effect_id, str) or not effect_id:
            return None
        with self._lock:
            return self._records.get(effect_id)

    def by_lease(self, lease_id: str) -> Optional[SideEffectRecord]:
        """The side-effect row bound to one lease, or ``None``."""

        if not isinstance(lease_id, str) or not lease_id:
            return None
        with self._lock:
            effect_id = self._by_lease.get(lease_id)
            if effect_id is None:
                return None
            return self._records.get(effect_id)

    def records(self) -> tuple[SideEffectRecord, ...]:
        """Every side-effect row, in insertion order."""

        with self._lock:
            return tuple(self._records.values())

    # ========================================================
    # Transitions
    # ========================================================

    def transition(
        self,
        effect_id: str,
        next_state: EffectState,
        *,
        attempt_id: Optional[str] = None,
        attempted_at: Optional[float] = None,
        observed_outcome: Optional[EffectOutcome] = None,
        observed_at: Optional[float] = None,
        evidence_kind: Optional[ReceiptKind] = None,
        external_request_id: Optional[str] = None,
        provider: Optional[str] = None,
        note: Optional[str] = None,
        receipt_authority_valid: Optional[bool] = None,
        attempt_authority_valid: Optional[bool] = None,
        terminal_reason: str = "",
        reason: str = "",
        details: Optional[dict[str, Any]] = None,
    ) -> Optional[SideEffectRecord]:
        """Atomically move a row from its current state to ``next_state``.

        Returns the new record on success and ``None`` when the row is
        absent or not in the state the transition expects -- the
        compare-and-set failed. ``None`` is never retried into success by
        the caller; it is a refusal.

        The state machine table is checked first, and the CAS is the
        enforcement: even a caller that checked nothing cannot move a
        terminal ``SUCCEEDED`` row again, which is what makes a replayed
        receipt unable to produce a second completion.

        A ``next_state`` equal to the current state is legal only for
        ``UNKNOWN`` (an explicit reconciliation that still cannot
        establish an outcome): it appends a history entry and refreshes
        the reconcile stamp without changing phase.

        Raises :class:`IllegalEffectTransitionError` for an edge the
        machine does not declare and :class:`EffectJournalError` when the
        backend refuses the write.
        """

        with self._lock:
            record = self._records.get(effect_id)

            if record is None:
                return None

            if not effect_transition_allowed(record.state, next_state):
                raise IllegalEffectTransitionError(
                    f"{record.state.value} -> {next_state.value} is not "
                    "a legal side-effect transition"
                )

            at = self._now()

            resolving = (
                record.state
                in (EffectState.ATTEMPT_STARTED, EffectState.UNKNOWN)
                and next_state
                in (
                    EffectState.UNKNOWN,
                    EffectState.SUCCEEDED,
                    EffectState.FAILED,
                )
            )

            next_record = replace(
                record,
                state=next_state,
                attempt_id=(
                    attempt_id if attempt_id is not None else record.attempt_id
                ),
                attempted_at=(
                    attempted_at
                    if attempted_at is not None
                    else record.attempted_at
                ),
                observed_outcome=(
                    observed_outcome
                    if observed_outcome is not None
                    else record.observed_outcome
                ),
                observed_at=(
                    observed_at if observed_at is not None else record.observed_at
                ),
                evidence_kind=(
                    evidence_kind
                    if evidence_kind is not None
                    else record.evidence_kind
                ),
                external_request_id=(
                    external_request_id
                    if external_request_id is not None
                    else record.external_request_id
                ),
                provider=(
                    provider if provider is not None else record.provider
                ),
                note=note if note is not None else record.note,
                receipt_authority_valid=(
                    receipt_authority_valid
                    if receipt_authority_valid is not None
                    else record.receipt_authority_valid
                ),
                attempt_authority_valid=(
                    attempt_authority_valid
                    if attempt_authority_valid is not None
                    else record.attempt_authority_valid
                ),
                reconcile_count=(
                    record.reconcile_count + 1 if resolving else record.reconcile_count
                ),
                last_reconciled_at=(
                    at if resolving else record.last_reconciled_at
                ),
                terminal_reason=(
                    terminal_reason
                    if terminal_reason
                    else record.terminal_reason
                ),
                history=record.history
                + ((record.state, next_state, at, reason),),
                details=(
                    dict(details)
                    if details is not None
                    else record.details
                ),
            )

            if (
                is_terminal_effect(next_state)
                and not next_record.terminal_reason
            ):
                next_record = replace(
                    next_record,
                    terminal_reason=reason or next_state.value,
                )

            # Persist before publishing in memory so a failed write never
            # leaves an in-memory state the backend does not hold.
            self._write_backend_transition(record, next_record)

            self._records[effect_id] = next_record

            return next_record

    def expire_lapsed(self) -> int:
        """Close intents whose deadline passed before any attempt began.

        Only ``INTENT_RECORDED`` rows may lapse, into ``FAILED`` with
        ``terminal_reason=effect_deadline_passed``: the row never left
        ``INTENT_RECORDED``, so the record itself proves nothing was ever
        transmitted, and confirming that the effect did not happen needs
        no external guess. An attempted row is never lapsed -- the action
        may genuinely be running, and deciding it did not is the guess
        this store refuses to make.
        """

        now = self._now()
        changed = 0

        with self._lock:
            for effect_id, record in list(self._records.items()):
                if is_terminal_effect(record.state):
                    continue
                if record.state is not EffectState.INTENT_RECORDED:
                    continue
                if record.expires_at > now:
                    continue

                try:
                    self.transition(
                        effect_id,
                        EffectState.FAILED,
                        reason="effect_deadline_passed",
                        terminal_reason="effect_deadline_passed",
                    )
                except _EffectCasRefused:
                    # Another process moved this row between read and write.
                    continue
                changed += 1

        return changed

    # ========================================================
    # Backend persistence
    # ========================================================

    def _write_backend_create(self, record: SideEffectRecord) -> None:
        if self._backend is None:
            return
        self._backend.insert(record)

    def _write_backend_transition(
        self,
        previous: SideEffectRecord,
        record: SideEffectRecord,
    ) -> None:
        if self._backend is None:
            return

        moved = self._backend.cas(
            previous.effect_id,
            previous.state,
            record,
        )

        if not moved:
            self._refresh_from_backend(previous.effect_id)
            raise _EffectCasRefused(previous.effect_id, previous.state)

    def _refresh_from_backend(self, effect_id: str) -> None:
        if self._backend is None:
            return

        try:
            current = self._backend.load_one(effect_id)
        except Exception:  # noqa: BLE001 - refresh is best effort
            current = None

        if current is None:
            previous = self._records.pop(effect_id, None)
            if previous is not None:
                self._by_lease.pop(previous.lease_id, None)
            return

        previous = self._records.get(effect_id)
        if previous is not None and previous.lease_id != current.lease_id:
            self._by_lease.pop(previous.lease_id, None)

        self._records[effect_id] = current
        self._by_lease[current.lease_id] = effect_id

    # ========================================================
    # Inspection
    # ========================================================

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

    def __enter__(self) -> "EffectJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class _EffectCasRefused(EffectJournalError):
    """Internal: the backend's compare-and-set matched no row.

    Converted by the enforcement path into a refused outcome. Not part of
    the public vocabulary -- callers see :class:`EffectResult`.
    """

    def __init__(self, effect_id: str, expected: EffectState):
        super().__init__(
            f"effect {effect_id[:8]}... is no longer in "
            f"{expected.value}; the transition was refused"
        )
        self.effect_id = effect_id
        self.expected = expected


__all__ = [
    "ALLOWED_EFFECT_TRANSITIONS",
    "DEFAULT_EFFECT_TTL_SECONDS",
    "EffectAlreadyBoundError",
    "EffectJournal",
    "EffectJournalError",
    "EffectOutcome",
    "EffectResult",
    "EffectState",
    "IllegalEffectTransitionError",
    "ReceiptKind",
    "SideEffectRecord",
    "TERMINAL_EFFECT_STATES",
    "canonical_effect_digest",
    "effect_transition_allowed",
    "is_terminal_effect",
]
