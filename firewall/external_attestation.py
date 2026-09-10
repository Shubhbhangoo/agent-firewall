"""External state attestation: whether an *external system* vouches for state.

v2.8 recorded an effect. v2.9 asked whether the *recorded claim* could be
trusted. Both stop at the same place, and v3.0 does not move the line:
everything the side-effect journal and the verification journal hold was
pushed into them by the process the firewall runs in. A ``SUCCEEDED``
receipt labelled ``provider_evidence`` is a label; a ``VERIFIED`` claim
produced by a deployment verifier is a check of that label. Neither is a
statement *by the external system*, signed with a key the external system
controls, about the state the external system is actually in. The firewall
could say "I recorded that the effect succeeded and my verifier agreed
with my record"; it could not say "the payment processor attests that this
transfer settled".

v3.1 draws that line, and it is the last line in a chain that already
refuses to blur its steps:

.. code-block:: text

    AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED
                              =/= ATTESTED =/= COMPLETED

``ATTESTED`` is a new, separately journaled claim: that a *signed
envelope produced outside this process*, naming exactly this effect,
attempt, execution and correlation handle, and carrying a validity window
the firewall is currently inside, verified against a public key the
deployment registered for a named external issuer. It answers the
question v2.9 could not: not "did my verifier accept my record", but "did
the external system authenticate this state, about this effect, now".

**What attestation establishes, and what it does not.** It establishes
*origin, scope, freshness and correlation*: that a named external issuer
holding a registered key signed this statement (origin), about exactly
this effect and attempt and no other (scope), inside a window that has not
closed and is not older than the deployment tolerates (freshness), naming
the same external request handle the effect row recorded (correlation),
and that the nonce on it has not been used before (non-replay). It does
not establish that the external system *told the truth*. A signature is a
statement about who said something, not about whether it is so. A
deployment that registers a key it also controls has attested its own
claim, and no cryptographic check can tell the difference between that
and the external system speaking; the firewall reports *who signed*, and
the trust decision stays with the operator who registered the key. This is
the honest statement of the guarantee, and it is repeated in
``docs/v3.1-external-attestation.md`` rather than implied.

**Attestation cannot become authorization.** Nothing here constructs an
``AuthorizationResult``, and nothing here writes to the lease journal, the
side-effect journal or the verification journal. The attestation journal
is a *fourth* journal beside them: an operator may archive it, throw it
away, or keep it without rewriting any of the other three. It is not read
by ``FirewallSDK.authorize()`` or by any gate on the ALLOW path -- the
release's invariant checks the census both ways, so a later change cannot
route an authorization decision through it. Its only effect on the rest of
the system is a refusal: a completion that requires attestation refuses
unless a *current* ``ATTESTED`` claim stands for exactly that effect, and
refusals can never widen authority. A remembered attestation never
resurrects a revoked or expired execution either: like a v2.9 ``VERIFIED``
verdict, an ``ATTESTED`` verdict may only be *recorded* while the
execution's authority basis still holds, and a signature arriving after
revocation is preserved truthfully as ``NOT_ATTESTED``.

**The binding is everything.** An attestation record is keyed to exactly
one (effect, attempt, external correlation):

* ``effect_id`` + ``lease_id`` + ``execution_id`` + ``attempt_id`` pin it
  to the one external effect of the one execution that adopted the
  protocol, and ``effect_digest`` pins it to the one effect payload --
  a re-signed envelope that names a different payload is a different
  statement about a different effect and is refused as a scope mismatch;
* ``capability_fingerprint``, ``agent_id``, ``action`` and
  ``idempotency_key`` pin it to the one authorized act, so an envelope
  cannot be lifted from one grant onto another;
* the issuer identity (``issuer_id`` + ``key_id`` + algorithm) and the
  envelope digest pin it to the one signature that produced it;
* the record's own id is the digest of that binding, so a forged, edited
  or replayed row disagrees with the id it claims and is refused, and a
  duplicate of the identical claim cannot be inserted twice.

**Freshness is checked twice, on purpose.** An envelope outside its own
validity window, or older than the deployment's maximum age, is refused
when it is presented; and every ``ATTESTED`` claim is re-checked for
freshness at the moment a completion relies on it. A claim that was true
when it was recorded and has since expired is *stale*, not satisfied, and
the completion gate says so by name (``attestation_stale_at_completion``)
rather than treating the journal as a permanent warrant. Nothing is
rewritten on expiry: the record still says what the issuer signed.

**Replay is refused by two independent mechanisms.** The envelope's scope
fields are inside the signature, so an envelope minted for one effect
cannot be presented for another -- the presentation fails the scope check
before the ledger is consulted. And a nonce ledger keyed by
``(issuer_id, nonce)`` records every nonce the firewall has accepted,
against the envelope and the effect it was accepted *for*; a nonce that
arrives again under a different envelope, or for a different effect, is
refused as ``attestation_replayed``. The ledger is written by the same
store as the records (``firewall/external_attestation_store.py``) so the
property survives a restart: an envelope accepted before a crash is not
fresh again afterwards.

**Contradictions are preserved, never resolved.** An attestation that
disagrees with what the effect row recorded is not dropped and not
silently preferred: a later conclusive attestation that contradicts an
earlier conclusive one is journaled as ``CONTRADICTED`` beside it, and the
completion gate trusts only the latest claim about the effect and refuses
outright while any contradiction stands. ``UNKNOWN`` asserts nothing about
what happened, so an attestation that resolves a recorded ``UNKNOWN`` into
``SUCCEEDED`` is a resolution rather than a contradiction -- which is the
one direction where the external system is genuinely telling the firewall
something the firewall could not establish for itself.

**Fail-closed on unavailability.** An unreadable clock, an unreadable
issuer trust store, a journal that cannot write, an envelope that will not
parse, an unsupported algorithm or version, an unknown or revoked issuer
key, a signature that does not verify, an absent state digest, an absent
correlation handle where the row recorded one -- each is a truthful
``NOT_ATTESTED`` record with a named reason and a refused result. A
refusal never raises in place of deciding, exactly as on the
authorization path.

This module is not the v2.0 :mod:`firewall.attest` layer. That one signs
statements about *agent identity* with keys the platform manages. This one
verifies statements about *external system state* against keys the
external system controls, and it never mints one: production code here has
no signing path at all.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from firewall.effect import EffectOutcome
from firewall.temporal import (
    TEMPORAL_ANOMALY_PREFIX,
    TemporalError,
    sample_temporal,
)

#: Envelope format version. Bumped when the signed block changes shape.
ATTESTATION_VERSION = 1

#: Signing algorithms this module can verify. Anything else is refused as
#: unsupported rather than guessed at -- the same rule the v2.0 attestation
#: verifier follows, for the same reason.
SUPPORTED_ALGORITHMS = ("Ed25519",)

#: The only statement type the firewall accepts. A signed envelope that
#: says it is about something else is not evidence about an effect, however
#: well it verifies.
STATEMENT_TYPE = "external_effect_state"

#: Default maximum age of an attestation, in seconds.
#:
#: An envelope carries its own ``expires_at``. This is the *deployment's*
#: additional ceiling on staleness: however long an issuer is willing to
#: warrant its statement, the firewall refuses to rely on one older than
#: this. Tightening it can only add refusals.
DEFAULT_MAX_AGE_SECONDS = 300.0


class AttestationError(ValueError):
    """An attestation envelope is malformed."""


class AttestationJournalError(Exception):
    """The attestation journal could not hold or produce its state."""


class ExternalIssuerError(ValueError):
    """An external issuer key could not be registered or revoked."""


# =====================================================================
# Canonical encoding
# =====================================================================


def _canonical_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding of a signed or digested structure.

    One encoding for every digest and every signature in this module, so a
    value that re-derives to a digest on one side re-derives to the same
    digest on the other. ``sort_keys`` makes the byte string independent of
    insertion order, and the compact separators make it independent of
    whitespace -- the two classic ways a "signature mismatch" turns out to
    be an encoding mismatch.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(text: Any, label: str) -> bytes:
    if not isinstance(text, str) or not text.strip():
        raise AttestationError(f"{label} must be base64 text")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise AttestationError(f"{label} is not valid base64") from exc


def _require_non_empty_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError(f"{label} must be a non-empty string")
    return value


def _require_finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AttestationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise AttestationError(f"{label} must be finite")
    return result


def _opt_str(value: Any, label: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AttestationError(f"{label} must be a string or None")
    return value


def canonical_external_state_digest(state: Any) -> str:
    """The digest an issuer computes over the external state it observed.

    Offered so that a deployment's attestation bridge and the firewall
    agree on what the field means: a stable digest of the state the issuer
    is asserting, computed over a canonical encoding. The firewall never
    recomputes it -- it cannot see the external system -- and never
    interprets it beyond preserving it verbatim inside the attested record,
    so an auditor holding the same state can check the issuer's arithmetic.
    """

    try:
        payload = _canonical_bytes(state if state is not None else {})
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"external state has no stable digest: {type(exc).__name__}"
        ) from exc

    return hashlib.sha256(payload).hexdigest()


# =====================================================================
# The envelope
# =====================================================================


@dataclass(frozen=True)
class AttestationEnvelope:
    """One signed statement by an external issuer about one effect.

    Produced *outside* this process by the external system, or by the
    deployment's bridge to it, and handed to
    :meth:`firewall.sdk.FirewallSDK.record_attestation` as data. The
    firewall treats it as untrusted input: every field below the signature
    is inside the signed block, so the signature is over all of it, and the
    verification path checks the fields again against the journal row
    rather than assuming the signature makes them true of *this* effect.

    ``issued_at`` / ``not_before`` / ``expires_at`` are the issuer's own
    validity window, in the same time base the firewall's clock reads (or
    inside the skew the deployment configured). ``nonce`` is the issuer's
    anti-replay handle: the pair ``(issuer_id, nonce)`` may be accepted
    once. ``state_digest`` is required, because an attestation that asserts
    an outcome without naming the state it observed is a claim about the
    world with nothing in it to correlate.

    ``signature`` is base64 Ed25519 over ``signed_bytes()``. Nothing else
    is signed, and nothing outside the block is trusted.
    """

    issuer_id: str
    key_id: str
    algorithm: str
    effect_id: str
    lease_id: str
    attempt_id: str
    effect_digest: str
    capability_fingerprint: str
    agent_id: str
    action: str
    idempotency_key: str
    external_request_id: str
    observed_outcome: str
    state_digest: str
    issued_at: float
    not_before: float
    expires_at: float
    nonce: str
    signature: str = ""
    execution_id: Optional[str] = None
    provider: Optional[str] = None
    statement_type: str = STATEMENT_TYPE
    attestation_version: int = ATTESTATION_VERSION
    claims: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # The signed block
    # ------------------------------------------------------------------

    def signed_block(self) -> dict[str, Any]:
        """Everything the signature covers, and nothing else.

        Deliberately a method rather than a cached value: the block is
        derived from the immutable fields at the moment it is needed, so a
        caller cannot hand in a block that disagrees with the envelope it
        claims to sign.
        """

        return {
            "attestation_version": self.attestation_version,
            "statement_type": self.statement_type,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "effect_id": self.effect_id,
            "lease_id": self.lease_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "effect_digest": self.effect_digest,
            "capability_fingerprint": self.capability_fingerprint,
            "agent_id": self.agent_id,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "external_request_id": self.external_request_id,
            "provider": self.provider,
            "observed_outcome": self.observed_outcome,
            "state_digest": self.state_digest,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "claims": dict(self.claims),
        }

    def signed_bytes(self) -> bytes:
        return _canonical_bytes(self.signed_block())

    @property
    def envelope_id(self) -> str:
        """The natural id of this statement: the digest of its signed block.

        Computed from the block rather than carried as a field, so a
        tampered envelope cannot keep an id that no longer describes it and
        a re-encoded identical envelope keeps the same id.
        """

        return hashlib.sha256(self.signed_bytes()).hexdigest()

    @property
    def asserted_outcome(self) -> Optional[EffectOutcome]:
        """``EffectOutcome`` for the asserted outcome, or ``None``.

        ``None`` rather than an exception: an envelope naming an outcome
        the firewall does not recognise is refused with that name, which is
        a decision, not a crash.
        """

        try:
            return EffectOutcome(self.observed_outcome)
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        block = self.signed_block()
        block["signature"] = self.signature
        return block

    @classmethod
    def from_dict(cls, data: Any) -> "AttestationEnvelope":
        """Parse a presented envelope, refusing anything malformed.

        Strict about shape and types, because the shape is what the
        signature covers: an envelope whose fields do not have the declared
        types cannot have been produced by :func:`build_attestation`, and a
        parser that coerced them would be inventing a block to verify. A
        parse failure is reported by the caller as
        ``attestation_malformed`` and refused; it is never turned into a
        verdict about the effect.
        """

        if not isinstance(data, dict):
            raise AttestationError(
                "an attestation envelope must be an object"
            )

        version = data.get("attestation_version", ATTESTATION_VERSION)
        if isinstance(version, bool) or not isinstance(version, int):
            raise AttestationError(
                "attestation_version must be an integer"
            )

        algorithm = _require_non_empty_str(
            data.get("algorithm", "Ed25519"), "algorithm"
        )

        claims = data.get("claims", {})
        if claims is None:
            claims = {}
        if not isinstance(claims, dict):
            raise AttestationError("claims must be an object")

        outcome = data.get("observed_outcome")
        if not isinstance(outcome, str) or not outcome.strip():
            raise AttestationError(
                "observed_outcome must be a non-empty string"
            )

        signature = data.get("signature", "")
        if not isinstance(signature, str):
            raise AttestationError("signature must be a string")

        return cls(
            issuer_id=_require_non_empty_str(
                data.get("issuer_id"), "issuer_id"
            ),
            key_id=_require_non_empty_str(
                data.get("key_id"), "key_id"
            ),
            algorithm=algorithm,
            effect_id=_require_non_empty_str(
                data.get("effect_id"), "effect_id"
            ),
            lease_id=_require_non_empty_str(
                data.get("lease_id"), "lease_id"
            ),
            attempt_id=_require_non_empty_str(
                data.get("attempt_id"), "attempt_id"
            ),
            effect_digest=_require_non_empty_str(
                data.get("effect_digest"), "effect_digest"
            ),
            capability_fingerprint=_require_non_empty_str(
                data.get("capability_fingerprint"),
                "capability_fingerprint",
            ),
            agent_id=_require_non_empty_str(
                data.get("agent_id"), "agent_id"
            ),
            action=_require_non_empty_str(
                data.get("action"), "action"
            ),
            idempotency_key=_require_non_empty_str(
                data.get("idempotency_key"), "idempotency_key"
            ),
            external_request_id=data.get("external_request_id") or "",
            observed_outcome=outcome,
            state_digest=data.get("state_digest") or "",
            issued_at=_require_finite(
                data.get("issued_at"), "issued_at"
            ),
            not_before=_require_finite(
                data.get("not_before", data.get("issued_at")),
                "not_before",
            ),
            expires_at=_require_finite(
                data.get("expires_at"), "expires_at"
            ),
            nonce=_require_non_empty_str(data.get("nonce"), "nonce"),
            signature=signature,
            execution_id=_opt_str(
                data.get("execution_id"), "execution_id"
            ),
            provider=_opt_str(data.get("provider"), "provider"),
            statement_type=_require_non_empty_str(
                data.get("statement_type", STATEMENT_TYPE),
                "statement_type",
            ),
            attestation_version=version,
            claims=dict(claims),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"AttestationEnvelope(issuer_id={self.issuer_id!r}, "
            f"effect={self.effect_id[:8]}..., "
            f"outcome={self.observed_outcome!r})"
        )


def build_attestation(
    *,
    issuer_id: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
    effect_id: str,
    lease_id: str,
    attempt_id: str,
    effect_digest: str,
    capability_fingerprint: str,
    agent_id: str,
    action: str,
    idempotency_key: str,
    state_digest: str,
    external_request_id: str = "",
    observed_outcome: Any = EffectOutcome.SUCCEEDED,
    execution_id: Optional[str] = None,
    provider: Optional[str] = None,
    issued_at: Optional[float] = None,
    ttl: float = DEFAULT_MAX_AGE_SECONDS,
    not_before: Optional[float] = None,
    nonce: Optional[str] = None,
    claims: Optional[dict[str, Any]] = None,
    algorithm: str = "Ed25519",
    clock: Any = None,
) -> AttestationEnvelope:
    """Sign one envelope over one effect. The issuer's side of the protocol.

    This is the *external system's* (or its bridge's) entry point, not the
    firewall's: the firewall has no code path that calls it, which the
    release's source census checks. It exists so a deployment can put an
    attestation bridge in front of a provider that speaks Ed25519, and so
    the test suite can mint genuine envelopes to attack with.

    ``issued_at`` defaults to ``clock()`` -- which defaults to wall time --
    and ``expires_at`` to ``issued_at + ttl``. Both are inside the signed
    block, so the issuer's window is the issuer's statement and cannot be
    widened afterwards by anyone who lacks the key. The boundary of the
    firewall's own clock is handled on the verifying side, by the skew the
    deployment configured, never here.
    """

    if not isinstance(private_key, Ed25519PrivateKey):
        raise AttestationError(
            "private_key must be an Ed25519PrivateKey"
        )

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise AttestationError(f"unsupported algorithm: {algorithm}")

    try:
        outcome = EffectOutcome(observed_outcome)
    except (TypeError, ValueError):
        raise AttestationError(
            f"observed_outcome is not a three-way outcome: "
            f"{observed_outcome!r}"
        ) from None

    if not isinstance(state_digest, str) or not state_digest.strip():
        raise AttestationError(
            "state_digest is required: an attestation that names no "
            "external state cannot be correlated with anything"
        )

    read_clock = clock if clock is not None else time.time

    if issued_at is None:
        try:
            issued_at = float(read_clock())
        except Exception as exc:  # noqa: BLE001 - reported as malformed
            raise AttestationError(
                f"issuer clock could not be read: {type(exc).__name__}"
            ) from exc

    issued_at = _require_finite(issued_at, "issued_at")
    ttl = _require_finite(ttl, "ttl")

    if ttl <= 0:
        raise AttestationError("ttl must be positive")

    expires_at = _require_finite(issued_at + ttl, "expires_at")
    start = (
        _require_finite(not_before, "not_before")
        if not_before is not None
        else issued_at
    )

    if expires_at <= start:
        raise AttestationError(
            "expires_at must be later than not_before"
        )

    envelope = AttestationEnvelope(
        issuer_id=_require_non_empty_str(issuer_id, "issuer_id"),
        key_id=_require_non_empty_str(key_id, "key_id"),
        algorithm=algorithm,
        effect_id=_require_non_empty_str(effect_id, "effect_id"),
        lease_id=_require_non_empty_str(lease_id, "lease_id"),
        attempt_id=_require_non_empty_str(attempt_id, "attempt_id"),
        effect_digest=_require_non_empty_str(
            effect_digest, "effect_digest"
        ),
        capability_fingerprint=_require_non_empty_str(
            capability_fingerprint, "capability_fingerprint"
        ),
        agent_id=_require_non_empty_str(agent_id, "agent_id"),
        action=_require_non_empty_str(action, "action"),
        idempotency_key=_require_non_empty_str(
            idempotency_key, "idempotency_key"
        ),
        external_request_id=(
            external_request_id if external_request_id is not None else ""
        ),
        observed_outcome=outcome.value,
        state_digest=state_digest,
        issued_at=issued_at,
        not_before=start,
        expires_at=expires_at,
        nonce=(
            nonce
            if isinstance(nonce, str) and nonce
            else uuid.uuid4().hex
        ),
        execution_id=execution_id,
        provider=provider,
        attestation_version=ATTESTATION_VERSION,
        claims=dict(claims or {}),
    )

    signature = private_key.sign(envelope.signed_bytes())

    return AttestationEnvelope(
        **{
            **{
                name: getattr(envelope, name)
                for name in envelope.__dataclass_fields__
            },
            "signature": _b64encode(signature),
        }
    )


def verify_envelope_signature(
    envelope: Any,
    public_key: Any,
) -> bool:
    """Whether ``envelope``'s signature verifies under ``public_key``.

    Total: a wrong type, a missing or non-base64 signature, an algorithm
    mismatch or an ``InvalidSignature`` all answer ``False``. A verifier
    that raised would hand the decision to whoever wrapped the call in
    ``try``/``except``, which is the failure mode every other boundary in
    this package refuses.
    """

    if not isinstance(envelope, AttestationEnvelope):
        return False

    if not isinstance(public_key, Ed25519PublicKey):
        return False

    try:
        signature = _b64decode(envelope.signature, "signature")
        public_key.verify(signature, envelope.signed_bytes())
    except (InvalidSignature, AttestationError, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001 - an unusable key is not a pass
        return False

    return True


# =====================================================================
# Verdicts and records
# =====================================================================


class AttestationOutcome(str, Enum):
    """What one attestation attempt concluded about one effect.

    Three verdicts, and the asymmetry between them is load-bearing, the
    same way it is in the verification journal. ``ATTESTED`` is the only
    verdict a completion may rely on, and it may only be *recorded* while
    the execution's authority basis still holds. ``NOT_ATTESTED`` and
    ``CONTRADICTED`` are recorded truthfully whenever they are what the
    check produced -- they can only refuse, so no authority check is
    needed to preserve them -- but ``CONTRADICTED`` says more than
    ``NOT_ATTESTED``: it is the explicit record that a signed statement
    disagreed with the effect, which is a finding about the external
    system rather than a missing piece of evidence.
    """

    ATTESTED = "attested"
    NOT_ATTESTED = "not_attested"
    CONTRADICTED = "contradicted"


def attestation_outcome_of(value: Any) -> Optional[AttestationOutcome]:
    """``AttestationOutcome`` from a member or its value; ``None`` otherwise."""

    try:
        return AttestationOutcome(value)
    except (TypeError, ValueError):
        return None


def freshness_failure(
    *,
    issued_at: Any,
    not_before: Any,
    expires_at: Any,
    now: float,
    max_age: float,
    skew: float = 0.0,
    effective_age: Optional[float] = None,
) -> Optional[str]:
    """``None`` when a validity window is fresh at ``now``, else the reason.

    One definition of freshness, used by the presentation check on an
    envelope and by the completion gate on a recorded claim, so the two can
    never disagree about whether an attestation is still good. The three
    questions are asked in the order that makes the answer most specific: a
    window the firewall has not entered yet (``not_yet_valid``), a window
    that has closed (``expired``), and a window that is still open but
    starts further back than the deployment tolerates (``stale``).

    ``skew`` widens only the *window* comparisons -- deployments whose
    clock and whose issuer's clock disagree -- and ``max_age`` is applied to
    unadjusted elapsed time, so a wide skew cannot make an old attestation
    new. Anything non-finite answers ``..._time_malformed`` rather than
    being coerced into a comparison: an unreadable time is not a fresh one.

    ``effective_age`` is v3.2's addition and the reason this signature has
    one. The age of an envelope is the one quantity here measured *against
    wall time* rather than against the issuer's signed window, and that
    makes it the one quantity a wall clock moved backwards can shrink: an
    attestation recorded at 12:00 and read at 12:10 is ten minutes old, and
    the same reading taken after the clock is set back to 12:01 makes it one
    minute old. So the caller may supply the age measured the other way --
    elapsed monotonic time since the envelope was recorded, added to the age
    it already had then -- and the comparison uses the **larger** of the
    two. The larger age can only make the answer staler, which is the only
    direction this check is allowed to move.
    """

    try:
        issued = float(issued_at)
        start = float(not_before)
        end = float(expires_at)
        moment = float(now)
        tolerance = float(skew)
        ceiling = float(max_age)
    except (TypeError, ValueError):
        return "attestation_time_malformed"

    for value in (issued, start, end, moment, tolerance, ceiling):
        if not math.isfinite(value):
            return "attestation_time_malformed"

    age = moment - issued

    if effective_age is not None:
        try:
            monotonic_age = float(effective_age)
        except (TypeError, ValueError):
            return "attestation_time_malformed"

        if not math.isfinite(monotonic_age):
            return "attestation_time_malformed"

        # The larger of two readings of the same age: wall time since the
        # issuer stamped it, and elapsed time since the firewall recorded
        # it plus the age it had then. A wall clock moved backwards can only
        # shrink the first, so the second bounds what the first may claim.
        age = max(age, monotonic_age)

    if moment + tolerance < start:
        return "attestation_not_yet_valid"

    if moment - tolerance > end:
        return "attestation_expired"

    if age > ceiling:
        return "attestation_stale"

    return None


def attestation_binding_digest(
    *,
    effect_id: str,
    attempt_id: str,
    envelope_id: str,
    issuer_id: str,
    key_id: str,
    outcome: AttestationOutcome,
) -> str:
    """The natural id of one attestation claim.

    The id digests everything the claim is bound to: the effect, the
    attempt, the exact envelope that was presented, the issuer that signed
    it and the verdict reached. A record whose stored fields do not
    re-derive to its own id is a forged record -- the release's invariant
    checks exactly that on every row. Re-deriving also makes a duplicate of
    the identical claim collide at the store (one row per claim), while a
    genuinely distinct claim -- a contradiction recorded against the same
    effect, an accepted envelope from a second issuer -- necessarily
    carries a different id and is stored beside the old one.

    ``reason``, ``note`` and the timestamps are deliberately *not* part of
    the id: they are commentary about the verdict, not the verdict. An
    idempotent re-presentation of the identical envelope therefore returns
    the original row instead of accumulating near-duplicates, and the
    invariant's job is to re-derive the same id from the stored fields.
    """

    payload = _canonical_bytes(
        {
            "effect_id": effect_id,
            "attempt_id": attempt_id,
            "envelope_id": envelope_id,
            "issuer_id": issuer_id,
            "key_id": key_id,
            "outcome": outcome.value,
        }
    )

    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ExternalIssuerKey:
    """One registered public key of one external issuer.

    Registration is a trust decision, and it is the whole of the firewall's
    authority over an attestation: the firewall has no way to check that
    the key belongs to the system the issuer id names. What it can do is
    refuse to verify anything signed by a key nobody registered, keep the
    registration monotone (a revoked key cannot be re-registered), and make
    the census of who may register one a checked property of the source.
    """

    issuer_id: str
    key_id: str
    algorithm: str
    public_key_b64: str
    fingerprint: str
    registered_at: float
    revoked_at: Optional[float] = None
    revoked_reason: str = ""
    note: Optional[str] = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def public_key(self) -> Optional[Ed25519PublicKey]:
        """The loaded public key, or ``None`` if it will not load.

        ``None`` rather than raising: a stored key that no longer parses is
        a key that verifies nothing, and the caller treats it as a refusal.
        """

        if self.algorithm != "Ed25519":
            return None

        try:
            raw = _b64decode(self.public_key_b64, "public key")
            return Ed25519PublicKey.from_public_bytes(raw)
        except Exception:  # noqa: BLE001 - unusable is not a pass
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_b64": self.public_key_b64,
            "fingerprint": self.fingerprint,
            "registered_at": self.registered_at,
            "revoked_at": self.revoked_at,
            "revoked_reason": self.revoked_reason,
            "note": self.note,
        }


def _public_key_material(public_key: Any) -> tuple[str, str]:
    """``(algorithm, base64)`` for a public key in any accepted form."""

    if isinstance(public_key, Ed25519PublicKey):
        return "Ed25519", _b64encode(public_key.public_bytes_raw())

    if isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
        if len(raw) != 32:
            raise ExternalIssuerError(
                "a raw Ed25519 public key must be 32 bytes"
            )
        try:
            Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - unusable material
            raise ExternalIssuerError(
                "the raw public key is not a valid Ed25519 key"
            ) from exc
        return "Ed25519", _b64encode(raw)

    if isinstance(public_key, str):
        raw = _b64decode(public_key, "public key")
        if len(raw) != 32:
            raise ExternalIssuerError(
                "a base64 Ed25519 public key must decode to 32 bytes"
            )
        try:
            Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - unusable material
            raise ExternalIssuerError(
                "the decoded public key is not a valid Ed25519 key"
            ) from exc
        return "Ed25519", _b64encode(raw)

    raise ExternalIssuerError(
        "public_key must be an Ed25519PublicKey, 32 raw bytes, or "
        "base64 of 32 bytes"
    )


class ExternalIssuerTrustStore:
    """The external issuers whose signatures the firewall will accept.

    Configuration, not durable state: a restart forgets it, and an SDK that
    cannot verify anything until an operator registers the keys again is
    failing closed, not losing data. Registration and revocation are
    deliberately asymmetric in one respect -- revocation is final for a
    ``(issuer_id, key_id)`` pair. Re-registering a revoked key is refused
    rather than silently un-revoking, because the whole point of revoking
    a compromised external key is that nobody can quietly put it back; a
    rotated replacement uses a new ``key_id``.

    Nothing here can widen authority: the store is read only by the
    attestation path, which is not on the ALLOW path at all, and the
    release's invariant requires that every mutator of this store is one of
    the SDK's declared registration methods.
    """

    def __init__(self, *, clock=None):
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._keys: dict[tuple[str, str], ExternalIssuerKey] = {}

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise ExternalIssuerError(
                "issuer trust store clock could not be read"
            ) from None

    def register(
        self,
        issuer_id: str,
        key_id: str,
        public_key: Any,
        *,
        algorithm: Optional[str] = None,
        note: Optional[str] = None,
    ) -> ExternalIssuerKey:
        """Register one external issuer key. The operator's trust decision."""

        issuer_id = _require_non_empty_str(issuer_id, "issuer_id")
        key_id = _require_non_empty_str(key_id, "key_id")

        if note is not None and not isinstance(note, str):
            raise ExternalIssuerError("note must be a string or None")

        resolved_algorithm, material = _public_key_material(public_key)

        if algorithm is not None and algorithm != resolved_algorithm:
            raise ExternalIssuerError(
                f"algorithm {algorithm!r} does not match the supplied key "
                f"material ({resolved_algorithm})"
            )

        if resolved_algorithm not in SUPPORTED_ALGORITHMS:
            raise ExternalIssuerError(
                f"unsupported algorithm: {resolved_algorithm}"
            )

        fingerprint = hashlib.sha256(
            base64.b64decode(material)
        ).hexdigest()

        record = ExternalIssuerKey(
            issuer_id=issuer_id,
            key_id=key_id,
            algorithm=resolved_algorithm,
            public_key_b64=material,
            fingerprint=fingerprint,
            registered_at=self._now(),
            note=note,
        )

        with self._lock:
            previous = self._keys.get((issuer_id, key_id))

            if previous is not None:
                if previous.revoked_at is not None:
                    raise ExternalIssuerError(
                        f"refusing to re-register revoked key "
                        f"{key_id!r} of issuer {issuer_id!r}; revocation "
                        "is final -- register a new key_id to rotate"
                    )
                raise ExternalIssuerError(
                    f"key {key_id!r} is already registered for issuer "
                    f"{issuer_id!r}"
                )

            self._keys[(issuer_id, key_id)] = record

        return record

    def revoke_key(
        self,
        issuer_id: str,
        key_id: str,
        *,
        reason: str = "",
    ) -> ExternalIssuerKey:
        """Withdraw one key. The signature stops being accepted immediately."""

        issuer_id = _require_non_empty_str(issuer_id, "issuer_id")
        key_id = _require_non_empty_str(key_id, "key_id")

        if not isinstance(reason, str):
            raise ExternalIssuerError("reason must be a string")

        with self._lock:
            record = self._keys.get((issuer_id, key_id))

            if record is None:
                raise ExternalIssuerError(
                    f"no such external issuer key: {issuer_id!r}/"
                    f"{key_id!r}"
                )

            if record.revoked_at is not None:
                return record

            revoked = ExternalIssuerKey(
                **{
                    **record.to_dict(),
                    "revoked_at": self._now(),
                    "revoked_reason": reason,
                }
            )
            self._keys[(issuer_id, key_id)] = revoked

        return revoked

    def revoke_issuer(
        self,
        issuer_id: str,
        *,
        reason: str = "",
    ) -> tuple[ExternalIssuerKey, ...]:
        """Withdraw every key of one issuer.

        The containment action for "the external system is compromised":
        every envelope it ever signed stops verifying, including ones that
        would otherwise still be inside their validity window.
        """

        issuer_id = _require_non_empty_str(issuer_id, "issuer_id")

        with self._lock:
            key_ids = [
                key_id
                for (candidate, key_id) in self._keys
                if candidate == issuer_id
            ]

            if not key_ids:
                raise ExternalIssuerError(
                    f"no such external issuer: {issuer_id!r}"
                )

        return tuple(
            self.revoke_key(issuer_id, key_id, reason=reason)
            for key_id in key_ids
        )

    def get(
        self,
        issuer_id: str,
        key_id: str,
    ) -> Optional[ExternalIssuerKey]:
        if not isinstance(issuer_id, str) or not isinstance(key_id, str):
            return None
        with self._lock:
            return self._keys.get((issuer_id, key_id))

    def is_trusted(self, issuer_id: str, key_id: str) -> bool:
        """Whether this exact key of this exact issuer may verify now.

        Unknown, unparseable and revoked all answer ``False``: this is a
        yes/no question about a signature, and "I could not tell" is not a
        yes.
        """

        record = self.get(issuer_id, key_id)

        if record is None or not record.active:
            return False

        return record.public_key() is not None

    def keys_for(self, issuer_id: str) -> tuple[ExternalIssuerKey, ...]:
        if not isinstance(issuer_id, str) or not issuer_id:
            return ()
        with self._lock:
            return tuple(
                record
                for (candidate, _), record in sorted(self._keys.items())
                if candidate == issuer_id
            )

    def issuers(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted({issuer for issuer, _ in self._keys})
            )

    def records(self) -> tuple[ExternalIssuerKey, ...]:
        with self._lock:
            return tuple(
                record for _, record in sorted(self._keys.items())
            )

    def size(self) -> int:
        with self._lock:
            return len(self._keys)


@dataclass(frozen=True)
class NonceClaim:
    """One ``(issuer_id, nonce)`` the firewall has accepted.

    Keyed by issuer as well as nonce, because nonces are the *issuer's*
    namespace: two external systems that both mint ``"abc123"`` are not
    replaying each other. The claim records which envelope it was accepted
    for and which effect it was accepted *against*, which is what makes
    cross-effect replay visible even before the scope check.
    """

    issuer_id: str
    nonce: str
    envelope_id: str
    effect_id: str
    attempt_id: str
    claimed_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "nonce": self.nonce,
            "envelope_id": self.envelope_id,
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "claimed_at": self.claimed_at,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "NonceClaim":
        if not isinstance(data, dict):
            raise AttestationJournalError(
                "a nonce claim must be an object"
            )
        try:
            return cls(
                issuer_id=_require_non_empty_str(
                    data.get("issuer_id"), "issuer_id"
                ),
                nonce=_require_non_empty_str(
                    data.get("nonce"), "nonce"
                ),
                envelope_id=str(data.get("envelope_id", "")),
                effect_id=str(data.get("effect_id", "")),
                attempt_id=str(data.get("attempt_id", "")),
                claimed_at=_require_finite(
                    data.get("claimed_at"), "claimed_at"
                ),
            )
        except AttestationError as exc:
            raise AttestationJournalError(str(exc)) from exc


@dataclass(frozen=True)
class AttestationRecord:
    """One immutable attestation claim about one recorded effect.

    The journal row is the authority on attestation state, exactly as the
    verification record is the authority on verification state: a forged,
    copied or edited row is refused because it disagrees with the id it
    claims. Everything below the binding fields is fixed at creation -- an
    attestation claim, once recorded, is never amended. Contradiction is
    handled by recording a *second* claim beside it, never by editing the
    first.

    The binding fields (effect, attempt, envelope, issuer, key, verdict)
    are what ``attestation_id`` digests. ``reason``, ``note``,
    ``recorded_at`` and ``details`` are commentary and do not participate,
    so re-recording the identical claim -- a crash-safe retry of the same
    presentation -- collides and returns the original.
    """

    attestation_id: str
    effect_id: str
    lease_id: str
    execution_id: Optional[str]
    attempt_id: str
    outcome: AttestationOutcome
    issuer_id: str
    key_id: str
    algorithm: str
    envelope_id: str
    nonce: str
    effect_digest: str
    capability_fingerprint: str
    agent_id: str
    action: str
    idempotency_key: str
    asserted_outcome: Optional[EffectOutcome]
    state_digest: str
    external_request_id: Optional[str]
    provider: Optional[str]
    #: Whether a correlation handle is present *and* consistent with what
    #: the effect row recorded. ``True`` for every ATTESTED claim.
    correlated: bool
    #: Where the correlation handle came from: the effect row's receipt
    #: (``receipt``), the signed envelope (``attestation``), or nowhere
    #: (``none``).
    correlation_source: str
    #: True only when a signature actually verified against a currently
    #: trusted, unrevoked key with a supported algorithm.
    signature_verified: bool
    issued_at: float
    not_before: float
    expires_at: float
    reason: str = ""
    note: Optional[str] = None
    recorded_at: float = 0.0
    #: The monotonic reading this claim was recorded at, and the process
    #: generation it belongs to. v3.2 keeps them because the *age* of an
    #: envelope is the one freshness quantity measured in wall time, and
    #: they are what let the completion gate measure that age the other
    #: way: ``recorded_at`` minus the envelope's ``issued_at`` is the age
    #: the claim already had, and elapsed monotonic time since
    #: ``recorded_monotonic`` extends it in a base a wall clock cannot move.
    #: Both are ``None`` for a claim recorded where no guard was bound,
    #: which is the honest reading -- nobody measured it.
    recorded_monotonic: Optional[float] = None
    temporal_generation: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "effect_id": self.effect_id,
            "lease_id": self.lease_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "outcome": self.outcome.value,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "envelope_id": self.envelope_id,
            "nonce": self.nonce,
            "effect_digest": self.effect_digest,
            "capability_fingerprint": self.capability_fingerprint,
            "agent_id": self.agent_id,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "asserted_outcome": (
                self.asserted_outcome.value
                if self.asserted_outcome is not None
                else None
            ),
            "state_digest": self.state_digest,
            "external_request_id": self.external_request_id,
            "provider": self.provider,
            "correlated": self.correlated,
            "correlation_source": self.correlation_source,
            "signature_verified": self.signature_verified,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "reason": self.reason,
            "note": self.note,
            "recorded_at": self.recorded_at,
            "recorded_monotonic": self.recorded_monotonic,
            "temporal_generation": self.temporal_generation,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AttestationRecord":
        """Reconstruct a record from its serialized form.

        Reconstruction is deliberately not trust: the enforcement path and
        the invariant both re-derive the id from the binding fields and
        refuse a record that does not match the id it claims. Malformed
        input is refused loudly -- a store row that cannot be reconstructed
        is a corrupt row.
        """

        if not isinstance(data, dict):
            raise AttestationJournalError(
                "attestation record data must be an object"
            )

        def _need_str(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise AttestationJournalError(
                    f"attestation field {key!r} must be a non-empty string"
                )
            return value

        def _finite(key: str) -> float:
            try:
                return _require_finite(data.get(key), key)
            except AttestationError as exc:
                raise AttestationJournalError(str(exc)) from exc

        def _opt_str_field(key: str) -> Optional[str]:
            try:
                return _opt_str(data.get(key), key)
            except AttestationError as exc:
                raise AttestationJournalError(str(exc)) from exc

        def _optional_finite(key: str) -> Optional[float]:
            value = data.get(key)

            if value is None:
                return None

            try:
                return _require_finite(value, key)
            except AttestationError as exc:
                raise AttestationJournalError(str(exc)) from exc

        def _optional_str(key: str) -> Optional[str]:
            return _opt_str_field(key)

        outcome = attestation_outcome_of(data.get("outcome"))
        if outcome is None:
            raise AttestationJournalError(
                "attestation field 'outcome' is not a verdict: "
                f"{data.get('outcome')!r}"
            )

        asserted_value = data.get("asserted_outcome")
        try:
            asserted_outcome = (
                EffectOutcome(asserted_value)
                if asserted_value is not None
                else None
            )
        except (TypeError, ValueError):
            raise AttestationJournalError(
                "attestation field 'asserted_outcome' is not an outcome: "
                f"{asserted_value!r}"
            ) from None

        for label in (
            "correlated",
            "signature_verified",
        ):
            if not isinstance(data.get(label), bool):
                raise AttestationJournalError(
                    f"attestation field {label!r} must be a boolean"
                )

        correlation_source = data.get("correlation_source")
        if correlation_source not in ("receipt", "attestation", "none"):
            raise AttestationJournalError(
                "attestation field 'correlation_source' must be one of "
                f"'receipt', 'attestation', 'none'; got "
                f"{correlation_source!r}"
            )

        note = data.get("note")
        if note is not None and not isinstance(note, str):
            raise AttestationJournalError(
                "attestation field 'note' must be a string or None"
            )

        reason = data.get("reason", "")
        if not isinstance(reason, str):
            raise AttestationJournalError(
                "attestation field 'reason' must be a string"
            )

        details = data.get("details", {})
        if not isinstance(details, dict):
            raise AttestationJournalError(
                "attestation field 'details' must be an object"
            )

        return cls(
            attestation_id=_need_str("attestation_id"),
            effect_id=_need_str("effect_id"),
            lease_id=_need_str("lease_id"),
            execution_id=_opt_str_field("execution_id"),
            attempt_id=_need_str("attempt_id"),
            outcome=outcome,
            issuer_id=str(data.get("issuer_id", "")),
            key_id=str(data.get("key_id", "")),
            algorithm=str(data.get("algorithm", "")),
            envelope_id=str(data.get("envelope_id", "")),
            nonce=str(data.get("nonce", "")),
            effect_digest=str(data.get("effect_digest", "")),
            capability_fingerprint=str(
                data.get("capability_fingerprint", "")
            ),
            agent_id=str(data.get("agent_id", "")),
            action=str(data.get("action", "")),
            idempotency_key=str(data.get("idempotency_key", "")),
            asserted_outcome=asserted_outcome,
            state_digest=str(data.get("state_digest", "")),
            external_request_id=_opt_str_field("external_request_id"),
            provider=_opt_str_field("provider"),
            correlated=data["correlated"],
            correlation_source=correlation_source,
            signature_verified=data["signature_verified"],
            issued_at=_finite("issued_at"),
            not_before=_finite("not_before"),
            expires_at=_finite("expires_at"),
            reason=reason,
            note=note,
            recorded_at=_finite("recorded_at"),
            recorded_monotonic=_optional_finite("recorded_monotonic"),
            temporal_generation=_optional_str("temporal_generation"),
            details=dict(details),
        )

    def rederived_id(self) -> str:
        """The id this record's binding fields actually produce."""

        return attestation_binding_digest(
            effect_id=self.effect_id,
            attempt_id=self.attempt_id,
            envelope_id=self.envelope_id,
            issuer_id=self.issuer_id,
            key_id=self.key_id,
            outcome=self.outcome,
        )

    def age_at(
        self,
        now: float,
        *,
        monotonic: Optional[float] = None,
        generation: Optional[str] = None,
    ) -> float:
        """How old the envelope is, taking the larger of two readings.

        Wall time since the issuer stamped it (``now - issued_at``) is the
        natural answer and the manipulable one: set the clock back and an
        old statement reads as a new one. Elapsed time since *this claim
        was recorded*, added to the age the envelope already had when it
        was recorded, is the answer a wall clock cannot move -- and it is
        only available within one process generation, because a monotonic
        clock is per-boot.

        Both are returned as the larger of the two, which is the only
        direction a staleness check may move. With no monotonic reading
        supplied (a deployment with no bound guard, or a claim recovered
        after a restart) the wall answer stands alone, exactly as it did
        before v3.2.
        """

        wall_age = now - self.issued_at

        if (
            monotonic is None
            or generation is None
            or self.recorded_monotonic is None
            or self.temporal_generation is None
            or generation != self.temporal_generation
        ):
            return wall_age

        age_at_recording = self.recorded_at - self.issued_at
        elapsed_since = monotonic - self.recorded_monotonic

        return max(wall_age, age_at_recording + elapsed_since)

    def fresh_at(
        self,
        now: float,
        *,
        max_age: float,
        skew: float = 0.0,
        monotonic: Optional[float] = None,
        generation: Optional[str] = None,
    ) -> Optional[str]:
        """``None`` when this record is fresh at ``now``, else the reason.

        The same arithmetic the presentation check runs, offered as a
        method so the completion gate and the invariant both ask one
        question one way. Only meaningful for an ``ATTESTED`` record, but
        total: any record answers, and the caller decides what the answer
        means. ``skew`` widens the window (deployments whose clock and
        issuer's clock disagree), and ``max_age`` bounds absolute staleness
        with *unadjusted* time, so a wide skew cannot make an old
        attestation new.

        ``monotonic`` / ``generation`` add v3.2's second reading of the
        age -- see :meth:`age_at` -- and can only make the answer staler.
        """

        return freshness_failure(
            issued_at=self.issued_at,
            not_before=self.not_before,
            expires_at=self.expires_at,
            now=now,
            max_age=max_age,
            skew=skew,
            effective_age=self.age_at(
                now,
                monotonic=monotonic,
                generation=generation,
            ),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"AttestationRecord(attestation_id={self.attestation_id[:8]}..., "
            f"outcome={self.outcome.value}, issuer={self.issuer_id!r}, "
            f"effect={self.effect_id[:8]}...)"
        )


@dataclass(frozen=True)
class AttestationResult:
    """The answer one attestation protocol operation returns.

    ``allowed`` is true only when an ``ATTESTED`` claim is on record for
    the exact effect and attempt the caller asked about, verified against a
    currently trusted external issuer key, and still fresh. Every refusal
    is a verdict-shaped ``False`` with a reason -- never an exception --
    and carries the record that *was* written when the verdict was a
    truthful ``NOT_ATTESTED`` or ``CONTRADICTED`` (both are preserved, and
    neither grants anything).

    ``record`` is the authoritative journal record after the attempt, or
    ``None`` when the presented effect did not name a row at all.
    """

    allowed: bool
    reason: str
    outcome: Optional[AttestationOutcome]
    record: Optional[AttestationRecord] = None

    @classmethod
    def refused(cls, reason: str) -> "AttestationResult":
        return cls(
            allowed=False,
            reason=reason,
            outcome=None,
            record=None,
        )


#: Outcome pairs that constitute a contradiction rather than a gap.
#:
#: ``UNKNOWN`` asserts nothing about what happened -- it explicitly says the
#: issuer could not establish it -- so it can never contradict anything. A
#: conclusive attestation that disagrees with a conclusive observation is
#: the contradiction this release detects. A conclusive attestation over a
#: recorded ``UNKNOWN`` is a *resolution*: the external system is telling
#: the firewall something it could not establish for itself.
CONCLUSIVE_OUTCOMES = frozenset(
    {EffectOutcome.SUCCEEDED, EffectOutcome.FAILED}
)


def contradiction_between(
    asserted: Optional[EffectOutcome],
    recorded: Optional[EffectOutcome],
) -> bool:
    """Whether two conclusive statements about one effect disagree."""

    if asserted not in CONCLUSIVE_OUTCOMES:
        return False

    if recorded not in CONCLUSIVE_OUTCOMES:
        return False

    return asserted is not recorded


#: The scope fields an attestation must echo exactly. ``(record attribute,
#: envelope attribute)`` pairs, with ``execution_id`` compared after
#: normalizing ``None`` to the empty string -- an execution that never
#: named an execution id and an envelope that names none agree.
SCOPE_FIELDS: tuple[tuple[str, str], ...] = (
    ("effect_id", "effect_id"),
    ("lease_id", "lease_id"),
    ("attempt_id", "attempt_id"),
    ("effect_digest", "effect_digest"),
    ("capability_fingerprint", "capability_fingerprint"),
    ("agent_id", "agent_id"),
    ("action", "action"),
    ("idempotency_key", "idempotency_key"),
)


def scope_mismatch(record: Any, envelope: Any) -> Optional[str]:
    """Why ``envelope`` does not speak about ``record``, if it does not.

    One definition of scope, used by the enforcement path and by the
    invariant. Returns the name of the first field that disagrees, or
    ``None``. The comparison is against the *journal row* -- never against
    caller-supplied arguments -- so an envelope cannot be pointed at a
    different effect by the caller.
    """

    for record_field, envelope_field in SCOPE_FIELDS:
        left = getattr(record, record_field, None)
        right = getattr(envelope, envelope_field, None)

        if left != right:
            return record_field

    left_execution = getattr(record, "execution_id", None) or ""
    right_execution = getattr(envelope, "execution_id", None) or ""

    if left_execution != right_execution:
        return "execution_id"

    return None


class AttestationJournal:
    """The authority on attestation claims.

    One row per distinct claim, where a claim is identified by its natural
    id -- the digest of (effect, attempt, envelope, issuer, key, verdict).
    Inserting the identical claim twice returns the existing row (a
    crash-safe retry is idempotent); inserting a genuinely different claim
    -- a contradiction, an accepted envelope from a second issuer -- stores
    it beside the first, so contradictory evidence is preserved rather than
    resolved. The journal decides *what was recorded*, never *what may
    complete*: it has no reference to any authority store and constructs no
    verdict of its own beyond the records handed to it.

    The nonce ledger lives here too, because the two are one property: an
    attestation is accepted once. The ledger is keyed by
    ``(issuer_id, nonce)`` and records the envelope and the effect the nonce
    was accepted for. Claiming a nonce is idempotent for an identical
    claim -- same envelope, same effect, same attempt -- so a crash between
    the claim and the record is recoverable by re-presenting the same
    envelope, while a nonce arriving under a different envelope or for a
    different effect is a replay and is refused.

    An optional persistent backend (see
    :class:`firewall.external_attestation_store.SQLiteExternalAttestationStore`)
    makes rows and nonce claims survive a process restart; the primary keys
    make the one-row-per-claim and one-claim-per-nonce properties hold
    across processes too. That matters more here than anywhere else in the
    package: an in-memory ledger would mean replay protection lasted only
    as long as the process did.
    """

    def __init__(
        self,
        *,
        clock=None,
        backend: Optional[Any] = None,
        max_age: float = DEFAULT_MAX_AGE_SECONDS,
        skew: float = 0.0,
    ):
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
            raise TypeError("max_age must be numeric")
        max_age = float(max_age)
        if not math.isfinite(max_age) or max_age <= 0:
            raise ValueError("max_age must be a finite positive number")

        if isinstance(skew, bool) or not isinstance(skew, (int, float)):
            raise TypeError("skew must be numeric")
        skew = float(skew)
        if not math.isfinite(skew) or skew < 0:
            raise ValueError(
                "skew must be a finite non-negative number"
            )

        self._clock = clock if clock is not None else time.time
        self._backend = backend
        self._lock = threading.RLock()
        self.max_age = max_age
        self.skew = skew
        self._records: dict[str, AttestationRecord] = {}
        self._by_effect: dict[str, list[str]] = {}
        self._nonces: dict[tuple[str, str], NonceClaim] = {}

        if backend is not None:
            for record in backend.load():
                self._records[record.attestation_id] = record
                self._by_effect.setdefault(
                    record.effect_id, []
                ).append(record.attestation_id)

            for claim in backend.load_nonces():
                self._nonces[(claim.issuer_id, claim.nonce)] = claim

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise AttestationJournalError(
                "attestation journal clock could not be read"
            ) from None

    def now(self) -> float:
        """The journal's own clock reading, for deadline comparison."""

        return self._now()

    def temporal_context(self):
        """A validated temporal context for this journal's clock.

        The journal's clock is the one it stamps ``recorded_at`` with, so it
        is the one every age comparison here must be taken in. Bound to a
        guard the reading is audited (v3.2); unbound the context is marked
        unprovable, which is what stops the journal from claiming a
        monotonic age it never measured.

        Raises :class:`~firewall.temporal.TemporalError` when the clock
        cannot be read, which every caller turns into a refusal.
        """

        return sample_temporal(
            self,
            name="attestation",
            fallback=self._clock,
        )

    def check_window(
        self,
        *,
        envelope: Any,
        record: Optional[Any] = None,
    ) -> Optional[str]:
        """Why an envelope's validity window is not current, or ``None``.

        The single definition of envelope freshness, and the declaration
        :data:`firewall.temporal.TEMPORAL_WINDOW_SITES` names for this
        module: the presentation check and the completion gate both come
        through here, so an attestation can never be current one way in one
        place and stale in another.

        Three answers, in the order that makes them most useful:

        * an **anomalous** temporal context is refused by name
          (``temporal_anomaly:*``): a window compared against a clock that
          just moved backwards is not a window;
        * the issuer's own window and the deployment's maximum age are
          evaluated by :func:`freshness_failure`, with the age taken as the
          larger of the wall reading and the monotonic one when ``record``
          can supply the latter;
        * otherwise ``None``.
        """

        try:
            context = self.temporal_context()
        except TemporalError:
            return "attestation_clock_unavailable"

        if not context.unguarded and not context.provable:
            return f"{TEMPORAL_ANOMALY_PREFIX}:{context.anomaly}"

        return freshness_failure(
            issued_at=getattr(envelope, "issued_at", None),
            not_before=getattr(envelope, "not_before", None),
            expires_at=getattr(envelope, "expires_at", None),
            now=context.wall,
            max_age=self.max_age,
            skew=self.skew,
            effective_age=(
                record.age_at(
                    context.wall,
                    monotonic=context.monotonic,
                    generation=context.generation,
                )
                if record is not None
                else None
            ),
        )

    # ========================================================
    # Nonce ledger
    # ========================================================

    def lookup_nonce(
        self,
        issuer_id: str,
        nonce: str,
    ) -> Optional[NonceClaim]:
        """What this ``(issuer, nonce)`` was previously accepted for."""

        if not isinstance(issuer_id, str) or not isinstance(nonce, str):
            return None

        with self._lock:
            return self._nonces.get((issuer_id, nonce))

    def claim_nonce(
        self,
        *,
        issuer_id: str,
        nonce: str,
        envelope_id: str,
        effect_id: str,
        attempt_id: str,
    ) -> tuple[bool, Optional[NonceClaim]]:
        """Claim one nonce; ``(claimed, existing)``.

        ``claimed`` is ``True`` when the ledger accepted the claim, which
        includes the idempotent case: the same nonce, the same envelope and
        the same effect. Any other arrangement -- a different envelope
        under the same nonce, or the same envelope claimed for a different
        effect -- answers ``(False, existing)`` and the caller records a
        replay refusal. Persisted before the answer is given, so a ledger
        that could not write does not report a claim it does not hold.
        """

        for label, value in (
            ("issuer_id", issuer_id),
            ("nonce", nonce),
            ("envelope_id", envelope_id),
            ("effect_id", effect_id),
            ("attempt_id", attempt_id),
        ):
            if not isinstance(value, str) or not value:
                raise AttestationJournalError(
                    f"{label} must be a non-empty string"
                )

        candidate = NonceClaim(
            issuer_id=issuer_id,
            nonce=nonce,
            envelope_id=envelope_id,
            effect_id=effect_id,
            attempt_id=attempt_id,
            claimed_at=self._now(),
        )

        with self._lock:
            existing = self._nonces.get((issuer_id, nonce))

            if existing is not None:
                identical = (
                    existing.envelope_id == envelope_id
                    and existing.effect_id == effect_id
                    and existing.attempt_id == attempt_id
                )
                return identical, existing

            if self._backend is not None:
                self._backend.claim_nonce(candidate)

            self._nonces[(issuer_id, nonce)] = candidate

        return True, candidate

    def nonce_claims(self) -> tuple[NonceClaim, ...]:
        """Every nonce the firewall has accepted, in key order."""

        with self._lock:
            return tuple(
                claim for _, claim in sorted(self._nonces.items())
            )

    # ========================================================
    # Record
    # ========================================================

    def record(
        self,
        *,
        effect_id: str,
        lease_id: str,
        execution_id: Optional[str],
        attempt_id: str,
        outcome: AttestationOutcome,
        reason: str,
        issued_at: float,
        not_before: float,
        expires_at: float,
        envelope_id: str = "",
        issuer_id: str = "",
        key_id: str = "",
        algorithm: str = "",
        nonce: str = "",
        effect_digest: str = "",
        capability_fingerprint: str = "",
        agent_id: str = "",
        action: str = "",
        idempotency_key: str = "",
        asserted_outcome: Optional[EffectOutcome] = None,
        state_digest: str = "",
        external_request_id: Optional[str] = None,
        provider: Optional[str] = None,
        correlated: bool = False,
        correlation_source: str = "none",
        signature_verified: bool = False,
        note: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AttestationRecord:
        """Record one attestation claim, or return its identical twin.

        The record's id is re-derived from the binding fields. Returns the
        existing record when the identical claim is already on the journal
        (idempotent retry), and the freshly written record otherwise.
        Raises :class:`AttestationJournalError` when the row cannot be
        persisted -- a claim must not be reported recorded when the journal
        could not write it.

        An ``ATTESTED`` verdict is held to a stronger standard than a
        refusal, because it is the only verdict anything can rely on: it
        must name an issuer, a key, a supported algorithm, an envelope, a
        nonce, a conclusive asserted outcome and a state digest, it must
        record that a signature verified, and it must be correlated. A row
        that claims to be attested without those is refused at the door, in
        addition to being a violation the invariant would report.
        """

        if not isinstance(outcome, AttestationOutcome):
            raise TypeError("outcome must be an AttestationOutcome")

        for label, value in (
            ("effect_id", effect_id),
            ("lease_id", lease_id),
            ("attempt_id", attempt_id),
        ):
            if not isinstance(value, str) or not value:
                raise AttestationJournalError(
                    f"{label} must be a non-empty string"
                )

        if execution_id is not None and (
            not isinstance(execution_id, str) or not execution_id
        ):
            raise AttestationJournalError(
                "execution_id must be a non-empty string or None"
            )

        for label, value in (
            ("envelope_id", envelope_id),
            ("issuer_id", issuer_id),
            ("key_id", key_id),
            ("algorithm", algorithm),
            ("nonce", nonce),
            ("effect_digest", effect_digest),
            ("capability_fingerprint", capability_fingerprint),
            ("agent_id", agent_id),
            ("action", action),
            ("idempotency_key", idempotency_key),
            ("state_digest", state_digest),
        ):
            if not isinstance(value, str):
                raise AttestationJournalError(
                    f"{label} must be a string"
                )

        if correlation_source not in ("receipt", "attestation", "none"):
            raise AttestationJournalError(
                f"correlation_source is not a source: "
                f"{correlation_source!r}"
            )

        if not isinstance(reason, str):
            raise AttestationJournalError("reason must be a string")

        for label, value in (
            ("correlated", correlated),
            ("signature_verified", signature_verified),
        ):
            if not isinstance(value, bool):
                raise AttestationJournalError(
                    f"{label} must be a boolean"
                )

        if asserted_outcome is not None and not isinstance(
            asserted_outcome, EffectOutcome
        ):
            raise TypeError(
                "asserted_outcome must be an EffectOutcome or None"
            )

        for label, value in (
            ("issued_at", issued_at),
            ("not_before", not_before),
            ("expires_at", expires_at),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise AttestationJournalError(
                    f"{label} must be numeric"
                )
            if not math.isfinite(float(value)):
                raise AttestationJournalError(
                    f"{label} must be finite"
                )

        if note is not None and not isinstance(note, str):
            raise AttestationJournalError(
                "note must be a string or None"
            )

        if details is not None and not isinstance(details, dict):
            raise AttestationJournalError(
                "details must be an object or None"
            )

        if outcome is AttestationOutcome.ATTESTED:
            missing = [
                label
                for label, value in (
                    ("envelope_id", envelope_id),
                    ("issuer_id", issuer_id),
                    ("key_id", key_id),
                    ("algorithm", algorithm),
                    ("nonce", nonce),
                    ("effect_digest", effect_digest),
                    ("capability_fingerprint", capability_fingerprint),
                    ("agent_id", agent_id),
                    ("action", action),
                    ("idempotency_key", idempotency_key),
                    ("state_digest", state_digest),
                )
                if not value
            ]

            if missing:
                raise AttestationJournalError(
                    "an ATTESTED claim must name "
                    + ", ".join(sorted(missing))
                )

            if algorithm not in SUPPORTED_ALGORITHMS:
                raise AttestationJournalError(
                    f"an ATTESTED claim must name a supported "
                    f"algorithm, not {algorithm!r}"
                )

            if not signature_verified:
                raise AttestationJournalError(
                    "an ATTESTED claim must record a verified signature"
                )

            if not correlated or not external_request_id:
                raise AttestationJournalError(
                    "an ATTESTED claim must be correlated with the "
                    "effect's external request handle"
                )

            if asserted_outcome not in CONCLUSIVE_OUTCOMES:
                raise AttestationJournalError(
                    "an ATTESTED claim must assert a conclusive outcome "
                    "(succeeded or failed)"
                )

        attestation_id = attestation_binding_digest(
            effect_id=effect_id,
            attempt_id=attempt_id,
            envelope_id=envelope_id,
            issuer_id=issuer_id,
            key_id=key_id,
            outcome=outcome,
        )

        # The row's own timestamp and monotonic anchor, taken in one
        # audited reading. A refusal must still be recordable while the
        # clock is questionable -- the refusal is the truth about what was
        # presented -- so an anomalous or unguarded context stamps the
        # wall reading and leaves the anchors absent rather than refusing
        # the write. What it must *not* do is claim a monotonic age it did
        # not measure, because an ``ATTESTED`` claim carrying one would
        # make the staleness check believe a clock it cannot trust.
        try:
            context = self.temporal_context()
        except TemporalError:
            recorded_at = self._now()
            recorded_monotonic = None
            temporal_generation = None
            if outcome is AttestationOutcome.ATTESTED:
                raise AttestationJournalError(
                    "an ATTESTED claim cannot be recorded while the "
                    "journal's clock is unreadable"
                )
        else:
            recorded_at = context.wall
            recorded_monotonic = (
                context.monotonic if context.provable else None
            )
            temporal_generation = (
                context.generation
                if context.provable and not context.unguarded
                else None
            )

            if (
                outcome is AttestationOutcome.ATTESTED
                and not context.provable
            ):
                raise AttestationJournalError(
                    "an ATTESTED claim cannot be recorded inside an "
                    f"anomalous temporal context: {context.anomaly}"
                )

        record = AttestationRecord(
            attestation_id=attestation_id,
            effect_id=effect_id,
            lease_id=lease_id,
            execution_id=execution_id,
            attempt_id=attempt_id,
            outcome=outcome,
            issuer_id=issuer_id,
            key_id=key_id,
            algorithm=algorithm,
            envelope_id=envelope_id,
            nonce=nonce,
            effect_digest=effect_digest,
            capability_fingerprint=capability_fingerprint,
            agent_id=agent_id,
            action=action,
            idempotency_key=idempotency_key,
            asserted_outcome=asserted_outcome,
            state_digest=state_digest,
            external_request_id=external_request_id,
            provider=provider,
            correlated=correlated,
            correlation_source=correlation_source,
            signature_verified=signature_verified,
            issued_at=float(issued_at),
            not_before=float(not_before),
            expires_at=float(expires_at),
            reason=reason,
            note=note,
            recorded_at=recorded_at,
            recorded_monotonic=recorded_monotonic,
            temporal_generation=temporal_generation,
            details=dict(details or {}),
        )

        with self._lock:
            existing = self._records.get(attestation_id)

            if existing is not None:
                return existing

            persisted = self._write_backend(record)

            if persisted is not None:
                # A concurrent presenter -- or this process after a crash --
                # already put the identical claim in the durable store. The
                # stored row is the authority, so it is what gets published
                # here rather than a second in-memory copy of the same
                # binding.
                self._records[persisted.attestation_id] = persisted
                self._by_effect.setdefault(
                    persisted.effect_id, []
                ).append(persisted.attestation_id)
                return persisted

            self._records[attestation_id] = record
            self._by_effect.setdefault(effect_id, []).append(
                attestation_id
            )

        return record

    # ========================================================
    # Lookup
    # ========================================================

    def get(self, attestation_id: str) -> Optional[AttestationRecord]:
        """The authoritative row for ``attestation_id``, or ``None``."""

        if not isinstance(attestation_id, str) or not attestation_id:
            return None
        with self._lock:
            return self._records.get(attestation_id)

    def by_effect(self, effect_id: str) -> tuple[AttestationRecord, ...]:
        """Every attestation claim recorded about one effect.

        Ordered oldest first -- insertion order. The *latest* claim about
        the effect is the one the completion gate may rely on; anything
        else is a superseded verdict or one recorded against another
        attempt.
        """

        if not isinstance(effect_id, str) or not effect_id:
            return ()
        with self._lock:
            ids = self._by_effect.get(effect_id, ())
            return tuple(
                self._records[attestation_id]
                for attestation_id in ids
                if attestation_id in self._records
            )

    def records(self) -> tuple[AttestationRecord, ...]:
        """Every attestation claim, in insertion order."""

        with self._lock:
            return tuple(self._records.values())

    # ========================================================
    # Backend persistence
    # ========================================================

    def _write_backend(
        self,
        record: AttestationRecord,
    ) -> Optional[AttestationRecord]:
        """Persist ``record``; return the stored twin when one exists.

        Backends answer a duplicate of an identical claim with the row they
        already hold, because the primary key *is* the claim's binding: a
        duplicate cannot be a different claim, only the same one arriving
        twice. Returning it lets the caller publish the authoritative row
        instead of failing a safe retry.
        """

        if self._backend is None:
            return None

        return self._backend.insert(record)

    # ========================================================
    # Inspection
    # ========================================================

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

    def __enter__(self) -> "AttestationJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = [
    "ATTESTATION_VERSION",
    "CONCLUSIVE_OUTCOMES",
    "DEFAULT_MAX_AGE_SECONDS",
    "SCOPE_FIELDS",
    "STATEMENT_TYPE",
    "SUPPORTED_ALGORITHMS",
    "AttestationEnvelope",
    "AttestationError",
    "AttestationJournal",
    "AttestationJournalError",
    "AttestationOutcome",
    "AttestationRecord",
    "AttestationResult",
    "ExternalIssuerError",
    "ExternalIssuerKey",
    "ExternalIssuerTrustStore",
    "NonceClaim",
    "attestation_binding_digest",
    "attestation_outcome_of",
    "build_attestation",
    "canonical_external_state_digest",
    "contradiction_between",
    "freshness_failure",
    "scope_mismatch",
    "verify_envelope_signature",
]
