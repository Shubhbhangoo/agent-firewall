"""Witness quorum integrity: no single external witness is a root of trust.

v3.4 moved the root of trust out of the firewall's own storage and then, in
its honest-non-guarantees list, admitted what it had built: *one* witness.
One key, one signature, one machine. A checkpoint became externally
confirmed because a thing said so -- and a thing that can be compromised,
subpoenaed, misconfigured, or simply wrong is a single point of failure
wearing the costume of a trust root. The v3.4 release closed the gap where
the firewall vouched for itself; it did not close the gap where the
firewall's witness vouched alone.

This module is the second half. The property is:

    a checkpoint becomes externally confirmed only when the configured
    threshold of distinct trusted witnesses independently authenticates
    the identical anchor state.

Everything below that sentence is machinery, and the machinery is organised
around one observation: **the hard part of a quorum is not counting, it is
refusing to count.** Any implementation can add up signatures. What makes a
quorum worth anything is what it declines to do when the evidence is
ambiguous -- when two witnesses disagree, when one witness says two things,
when a receipt is old, when the policy it was signed under is not the policy
in force. Each of those has a name here and each one refuses, because the
alternative answer -- pick the version that is more convenient and carry on
-- is how a quorum silently becomes a single witness again.

**Equivocation is evidence, not an error to be resolved.** If one witness
signs conflicting digests for the same anchor and sequence, this module
keeps *both* signed statements, records the conflict, refuses the
contradictory vote, and exposes the pair through the SDK. Deciding which of
the two was "really" the witness's opinion would require knowledge this
firewall does not have and must not pretend to: a witness that signed both
is a witness whose signature means one thing less than it did, and the only
safe response is to stop counting it and say why.

**Nothing here can widen authority.** Every verdict this module produces is
a refusal or an abstention. It constructs no ``AuthorizationResult``, the
invariant checks that in both directions, and no function on the ALLOW path
references quorum state at all -- the same rule v3.4 set for anchoring, for
the same reason: a layer that exists to refuse must never be consulted when
the question is whether to permit.

**What a quorum buys, and what it does not.** It converts "one system said
so" into "N independent systems said so", which is a real gain against a
single compromised or mistaken witness and no gain at all against an
attacker who reaches the threshold. It is not consensus: there is no
leader, no term, no replicated log, no view change, and no liveness
protocol. If the witnesses cannot be reached the deployment stops
progressing, and this module reports that rather than working around it.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from firewall.anchor import (
    AnchorCheckpoint,
    AnchorKind,
    _canonical_bytes,
    anchor_kind_of,
)

#: Domain separator, so nothing computed here can be confused with a digest
#: computed by any other layer -- including v3.4's, whose signatures cover a
#: different domain string over overlapping field names.
QUORUM_DOMAIN = "agent-firewall/witness-quorum/v1"

#: The signing algorithm this module can verify. One algorithm, refused
#: rather than negotiated: an algorithm the module does not implement must
#: never become a way in.
SUPPORTED_QUORUM_ALGORITHMS = ("Ed25519",)


# =====================================================================
# Errors
# =====================================================================


class QuorumError(Exception):
    """Base error for the witness quorum layer.

    Every subclass names one way a quorum can fail to be provable and
    carries the refusal-reason fragment the boundary would use, so an
    operator reading an audit trail sees which property broke rather than
    that "something went wrong".
    """

    reason = "anchor_quorum_error"


class QuorumUnconfirmedError(QuorumError):
    """No quorum has been reached for this anchor and the gate is on."""

    reason = "anchor_quorum_unconfirmed"


class QuorumInsufficientError(QuorumError):
    """Fewer distinct trusted witnesses voted than the policy requires."""

    reason = "anchor_quorum_insufficient"


class QuorumSplitError(QuorumError):
    """Trusted witnesses authenticated conflicting statements about one anchor."""

    reason = "anchor_quorum_split"


class QuorumEquivocationError(QuorumError):
    """One witness signed two different statements about the same position."""

    reason = "anchor_witness_equivocation"


class QuorumPolicyError(QuorumError):
    """A receipt or binding was presented under a policy that is not in force."""

    reason = "anchor_policy_mismatch"


class QuorumDuplicateWitnessError(QuorumError):
    """One witness tried to cast more than one vote in one round."""

    reason = "anchor_witness_duplicate"


class QuorumStaleReceiptError(QuorumError):
    """A receipt described a position this anchor has already moved past."""

    reason = "anchor_witness_stale"


class QuorumUntrustedWitnessError(QuorumError):
    """A receipt was signed by an identity the active policy does not trust."""

    reason = "anchor_witness_untrusted"


class QuorumSignatureError(QuorumError):
    """A receipt does not re-derive, or its signature does not verify."""

    reason = "anchor_witness_invalid_signature"


class QuorumCheckpointMismatchError(QuorumError):
    """A receipt authenticates a checkpoint this anchor is not bound to."""

    reason = "anchor_checkpoint_mismatch"


class QuorumStoreError(QuorumError):
    """The quorum store could not be read, or refused what it was given."""

    reason = "anchor_quorum_unverifiable"


# =====================================================================
# Findings
# =====================================================================


@dataclass(frozen=True)
class QuorumFinding:
    """One refused quorum operation, kept as evidence of the attempt.

    A finding is not a violation: it is the mechanism working. It is kept so
    an operator can see that something tried to vote twice under one
    identity, or that two witnesses disagreed about what an anchor says --
    and so the invariant can tell "an attack was attempted and refused" from
    "the quorum says something untrue".
    """

    kind: str
    anchor_kind: str
    anchor_id: str
    sequence: int
    witness_id: str
    policy_id: str
    detail: str
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "witness_id": self.witness_id,
            "policy_id": self.policy_id,
            "detail": self.detail,
            "at": self.at,
        }


#: The finding kinds this release produces. Anything else is a finding the
#: invariant cannot explain, which it reports rather than ignoring.
QUORUM_FINDING_KINDS: frozenset[str] = frozenset(
    {
        #: Fewer distinct trusted witnesses voted than the threshold.
        "quorum_insufficient",
        #: Trusted witnesses authenticated conflicting statements.
        "quorum_split",
        #: One witness signed two different things about one position.
        "witness_equivocation",
        #: One witness tried to cast a second vote in one round.
        "witness_duplicate",
        #: A receipt described a position the anchor has moved past.
        "witness_stale",
        #: A receipt came from an identity the policy does not trust.
        "witness_untrusted",
        #: A receipt does not re-derive, or does not verify.
        "witness_invalid_signature",
        #: A receipt or binding named a policy that is not in force.
        "policy_mismatch",
        #: A receipt authenticated a checkpoint the anchor is not bound to.
        "checkpoint_mismatch",
        #: A backend that could not be read or written.
        "unverifiable",
        #: Persisted state that no longer re-derives to its stored id.
        "tampered",
    }
)


# =====================================================================
# Policy
# =====================================================================


def _canonical_pair_list(values: Any) -> list[str]:
    """A sorted list of distinct non-empty strings, or a refusal.

    Sorted so the policy id does not depend on the order an operator
    happened to list witnesses in: two deployments that configure the same
    three witnesses must arrive at the same policy id, or "is this the
    policy in force" becomes a question about list ordering.
    """

    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple, set, frozenset)):
        raise QuorumPolicyError("witness_ids must be a sequence of ids")

    seen: list[str] = []

    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise QuorumPolicyError("each witness id must be a non-empty string")

        if value not in seen:
            seen.append(value)

    if not seen:
        raise QuorumPolicyError("a policy must name at least one witness")

    return sorted(seen)


@dataclass(frozen=True)
class WitnessPolicy:
    """Which witnesses must agree, and how many of them.

    **The policy id is derived, not asserted.** ``policy_id`` is the digest
    of the threshold and the witness set over the canonical encoding, so an
    operator cannot mint an id that claims a different policy than the one
    its own fields describe. That is what makes the id immutable in the
    sense that matters: not "nobody can write it" -- a database row is a
    database row -- but "nobody can write it *and* have the fields agree",
    which is the only place a forger's work would show.

    A policy is thus *content-addressed*: the same threshold and witness set
    is the same policy, and a policy row whose id does not re-derive from
    its fields is a forged or edited one. Both directions are checked --
    by the journal when a policy is registered, by the store before a row
    is written, and by the invariant over every persisted row.

    An operator-chosen threshold is a trust decision this package cannot
    audit: 1-of-5 is a single witness with four bystanders, and this module
    will happily run it. That limitation is stated rather than engineered
    away, because refusing a weak threshold would mean the layer gets to
    overrule the deployment's own risk assessment from inside the process
    it is supposed to be independent of.
    """

    threshold: int
    witness_ids: tuple[str, ...]
    policy_id: str = ""
    created_at: float = 0.0

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @classmethod
    def derive(
        cls,
        threshold: int,
        witness_ids: Any,
        *,
        created_at: Optional[float] = None,
    ) -> "WitnessPolicy":
        """Build a policy whose id is the digest of its own content."""

        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise QuorumPolicyError("threshold must be an integer")

        if threshold < 1:
            raise QuorumPolicyError("threshold must be at least 1")

        ids = tuple(_canonical_pair_list(witness_ids))

        if threshold > len(ids):
            raise QuorumPolicyError(
                f"threshold {threshold} exceeds the {len(ids)} witness(es) "
                "the policy names, so it can never be met"
            )

        stamp = 0.0 if created_at is None else float(created_at)

        return cls(
            threshold=int(threshold),
            witness_ids=ids,
            policy_id=cls._derive_id(int(threshold), ids),
            created_at=stamp,
        )

    @staticmethod
    def _derive_id(threshold: int, witness_ids: tuple[str, ...]) -> str:
        return hashlib.sha256(
            _canonical_bytes(
                {
                    "domain": QUORUM_DOMAIN,
                    "threshold": int(threshold),
                    "witness_ids": list(witness_ids),
                }
            )
        ).hexdigest()

    def rederived_id(self) -> str:
        """The id this policy's own fields describe."""

        return self._derive_id(self.threshold, self.witness_ids)

    def rederives(self) -> bool:
        return self.policy_id == self.rederived_id()

    def trusts(self, witness_id: Any) -> bool:
        return isinstance(witness_id, str) and witness_id in self.witness_ids

    @property
    def size(self) -> int:
        return len(self.witness_ids)

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "threshold": int(self.threshold),
            "witness_ids": list(self.witness_ids),
            "created_at": float(self.created_at),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "WitnessPolicy":
        if not isinstance(payload, dict):
            raise QuorumPolicyError("a witness policy must be an object")

        threshold = payload.get("threshold")

        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise QuorumPolicyError("threshold must be an integer")

        created_at = payload.get("created_at", 0.0)

        if isinstance(created_at, bool) or not isinstance(
            created_at, (int, float)
        ):
            raise QuorumPolicyError("created_at must be a number")

        policy = cls.derive(
            threshold,
            payload.get("witness_ids"),
            created_at=float(created_at),
        )

        declared = payload.get("policy_id", "")

        # A declared id that disagrees with the content is not a policy, it
        # is a claim about a policy. Keeping the declared id would let a
        # caller bind a checkpoint to "the 3-of-5 policy" while presenting
        # 1-of-5 fields, which is the downgrade this module exists to
        # refuse. The derived id wins, and the disagreement is the caller's
        # problem to notice -- the invariant notices it too, because the row
        # will not re-derive to what the store recorded.
        if isinstance(declared, str) and declared and declared != policy.policy_id:
            raise QuorumPolicyError(
                "the policy id does not re-derive from its threshold and "
                "witness set"
            )

        return policy


# =====================================================================
# Receipts
# =====================================================================


@dataclass(frozen=True)
class QuorumReceipt:
    """One witness's authenticated statement about one anchor at one position.

    **The six fields a vote must agree on.** ``anchor_kind``, ``anchor_id``,
    ``sequence``, ``digest``, ``checkpoint_id`` and ``policy_id`` are all
    inside the signed block, so a receipt cannot be re-pointed at another
    anchor, another position, another value, or another policy after the
    fact: moving any of them moves the signature. This is what makes
    "replay across anchors" and "replay across policies" not merely
    detected but *unrepresentable* -- the bytes that would do it are bytes
    the witness never signed.

    ``receipt_id`` is the digest of everything below the signature, so a
    receipt whose stored id does not re-derive from its own fields is a
    forged or edited one. ``issued_at`` is the *witness's* statement about
    time and carries no guarantee; the monotone ``sequence`` orders
    positions, not the clock.

    Two receipts from one witness for one position are never two votes,
    whether they say the same thing or different things. The first case is
    a duplicate and the second is equivocation; both refuse, and they are
    named differently because an operator reading the audit trail needs to
    tell a retry from a compromised witness.
    """

    anchor_kind: str
    anchor_id: str
    sequence: int
    digest: str
    checkpoint_id: str
    policy_id: str
    witness_id: str
    algorithm: str = "Ed25519"
    issued_at: float = 0.0
    signature: str = ""
    receipt_id: str = ""

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def signed_payload(self) -> bytes:
        """Everything the signature covers, and nothing else.

        The signature and the receipt id are deliberately outside the
        block: a signature cannot cover itself, and a receipt whose id
        included its own signature could never re-derive.
        """

        return _canonical_bytes(
            {
                "domain": QUORUM_DOMAIN,
                "anchor_kind": self.anchor_kind,
                "anchor_id": self.anchor_id,
                "sequence": int(self.sequence),
                "digest": self.digest,
                "checkpoint_id": self.checkpoint_id,
                "policy_id": self.policy_id,
                "witness_id": self.witness_id,
                "algorithm": self.algorithm,
                "issued_at": self.issued_at,
            }
        )

    def rederived_id(self) -> str:
        return hashlib.sha256(self.signed_payload()).hexdigest()

    def rederives(self) -> bool:
        return self.receipt_id == self.rederived_id()

    def is_signed(self) -> bool:
        return bool(self.signature) and bool(self.witness_id)

    @property
    def statement(self) -> tuple[str, str]:
        """The two fields a witness's *opinion* lives in.

        Two receipts with the same statement agree even if they were issued
        at different times; two receipts with different statements are a
        conflict, whether they came from one witness or from several.
        """

        return (self.digest, self.checkpoint_id)

    @property
    def position(self) -> tuple[str, str, int]:
        """The anchor position this receipt is about."""

        return (self.anchor_kind, self.anchor_id, int(self.sequence))

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "digest": self.digest,
            "checkpoint_id": self.checkpoint_id,
            "policy_id": self.policy_id,
            "witness_id": self.witness_id,
            "algorithm": self.algorithm,
            "issued_at": self.issued_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "QuorumReceipt":
        """Rebuild a receipt from stored or received bytes.

        Every field is validated rather than coerced. A parser that
        tolerated a wrong type would be inventing a receipt to count, and
        the one thing this layer must never do is count something nobody
        signed.
        """

        if not isinstance(payload, dict):
            raise QuorumSignatureError("a quorum receipt must be an object")

        kind = anchor_kind_of(payload.get("anchor_kind"))

        if kind is None:
            raise QuorumSignatureError(
                f"unknown anchor kind: {payload.get('anchor_kind')!r}"
            )

        anchor_id = payload.get("anchor_id")

        if not isinstance(anchor_id, str) or not anchor_id.strip():
            raise QuorumSignatureError(
                "anchor_id must be a non-empty string"
            )

        sequence = payload.get("sequence")

        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise QuorumSignatureError("sequence must be an integer")

        if sequence < 0:
            raise QuorumSignatureError("sequence must not be negative")

        digest = payload.get("digest")

        if not isinstance(digest, str) or not digest.strip():
            raise QuorumSignatureError("digest must be a non-empty string")

        issued_at = payload.get("issued_at", 0.0)

        if isinstance(issued_at, bool) or not isinstance(
            issued_at, (int, float)
        ):
            raise QuorumSignatureError("issued_at must be a number")

        algorithm = payload.get("algorithm", "Ed25519")

        if algorithm not in SUPPORTED_QUORUM_ALGORITHMS:
            raise QuorumSignatureError(
                f"unsupported algorithm: {algorithm!r}"
            )

        for label in (
            "checkpoint_id",
            "policy_id",
            "witness_id",
            "signature",
            "receipt_id",
        ):
            value = payload.get(label, "")

            if not isinstance(value, str):
                raise QuorumSignatureError(f"{label} must be a string")

        return cls(
            anchor_kind=kind.value,
            anchor_id=anchor_id,
            sequence=int(sequence),
            digest=digest,
            checkpoint_id=payload.get("checkpoint_id", ""),
            policy_id=payload.get("policy_id", ""),
            witness_id=payload.get("witness_id", ""),
            algorithm=algorithm,
            issued_at=float(issued_at),
            signature=payload.get("signature", ""),
            receipt_id=payload.get("receipt_id", ""),
        )


def verify_receipt_signature(
    receipt: QuorumReceipt,
    public_key: Ed25519PublicKey,
) -> bool:
    """Whether ``receipt`` carries a valid signature under ``public_key``.

    Returns a boolean rather than raising, because every caller here is
    deciding a verdict and a verdict belongs in a return value. A malformed
    signature is ``False``, not an exception: "I could not verify this" and
    "this does not verify" are the same answer on a progression path.
    """

    if not receipt.is_signed():
        return False

    try:
        signature = base64.b64decode(
            receipt.signature.encode("ascii"), validate=True
        )
    except Exception:  # noqa: BLE001 - any decode failure
        return False

    try:
        public_key.verify(signature, receipt.signed_payload())
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - any verification failure
        return False

    return True


# =====================================================================
# Witnesses
# =====================================================================


class QuorumWitness:
    """The interface a quorum witness must satisfy.

    A quorum witness is an identity that holds a signing key the firewall
    does not, and that will authenticate an anchor state on request. What
    makes N of them worth more than one is a fact about the operator's
    infrastructure -- separate machines, separate operators, separate
    failure domains -- and this package cannot check it, so it ships the
    interface rather than a claim.
    """

    def sign(self, receipt: QuorumReceipt) -> QuorumReceipt:
        raise NotImplementedError


class InProcessQuorumWitness(QuorumWitness):
    """A witness held by the process it is supposed to be independent of.

    **This is not an independent witness.** It provides no independence
    whatsoever, and a deployment that uses it for a real quorum has built
    v3.4 with extra steps: one process holding N keys is one witness
    wearing N hats, and a compromise of that process satisfies every
    threshold at once.

    It exists for the three callers that cannot have independence by
    construction and no others: the invariant estate, which needs N things
    that sign so ``WITNESS_QUORUM_SOUNDNESS`` has state to inspect; the
    test suite, which needs to mint genuine and deliberately broken
    receipts to attack the layer with; and the benchmark file, which
    measures the protocol rather than a transport. All three run in one
    process. A deployment that wants the property wants N witnesses this
    process cannot reach.
    """

    def __init__(
        self,
        *,
        witness_id: str,
        private_key: Ed25519PrivateKey,
    ):
        if not isinstance(witness_id, str) or not witness_id.strip():
            raise QuorumSignatureError(
                "witness_id must be a non-empty string"
            )

        if not isinstance(private_key, Ed25519PrivateKey):
            raise QuorumSignatureError(
                "private_key must be an Ed25519PrivateKey"
            )

        self.witness_id = witness_id
        self._private_key = private_key

    def sign(self, receipt: QuorumReceipt) -> QuorumReceipt:
        if not isinstance(receipt, QuorumReceipt):
            raise TypeError("receipt must be a QuorumReceipt")

        stamped = replace(
            receipt,
            witness_id=self.witness_id,
            algorithm="Ed25519",
            signature="",
            receipt_id="",
        )

        return replace(
            stamped,
            signature=base64.b64encode(
                self._private_key.sign(stamped.signed_payload())
            ).decode("ascii"),
            receipt_id=stamped.rederived_id(),
        )


# =====================================================================
# Bindings, decisions, participation, evidence
# =====================================================================


@dataclass(frozen=True)
class CheckpointPolicyBinding:
    """The cryptographic binding between one checkpoint and one policy.

    A checkpoint is bound to the policy in force when it is published, and
    the binding is *derived* from the pair rather than asserted about it:
    ``binding_id`` is the digest of the checkpoint's identity and the
    policy's id, so neither side can be swapped afterwards without the
    binding failing to re-derive.

    This is what makes a policy downgrade detectable. Re-binding a
    confirmed checkpoint to a weaker policy would produce a second binding
    with a different id at the same checkpoint, and one checkpoint holds
    one binding -- the second is refused by name rather than recorded
    beside the first, because two accounts of what a checkpoint was
    anchored under is exactly the ambiguity a quorum is supposed to
    eliminate.
    """

    checkpoint_id: str
    anchor_kind: str
    anchor_id: str
    sequence: int
    digest: str
    policy_id: str
    binding_id: str = ""
    at: float = 0.0

    @classmethod
    def derive(
        cls,
        checkpoint: Any,
        policy_id: str,
        *,
        at: Optional[float] = None,
    ) -> "CheckpointPolicyBinding":
        if not isinstance(checkpoint, AnchorCheckpoint):
            raise QuorumCheckpointMismatchError(
                "a binding needs the checkpoint it binds"
            )

        if not isinstance(policy_id, str) or not policy_id.strip():
            raise QuorumPolicyError("policy_id must be a non-empty string")

        return cls(
            checkpoint_id=checkpoint.checkpoint_id,
            anchor_kind=checkpoint.kind.value,
            anchor_id=checkpoint.anchor_id,
            sequence=int(checkpoint.sequence),
            digest=checkpoint.digest,
            policy_id=policy_id,
            binding_id=cls._derive_id(
                checkpoint.checkpoint_id,
                checkpoint.kind.value,
                checkpoint.anchor_id,
                int(checkpoint.sequence),
                checkpoint.digest,
                policy_id,
            ),
            at=0.0 if at is None else float(at),
        )

    @staticmethod
    def _derive_id(
        checkpoint_id: str,
        anchor_kind: str,
        anchor_id: str,
        sequence: int,
        digest: str,
        policy_id: str,
    ) -> str:
        return hashlib.sha256(
            _canonical_bytes(
                {
                    "domain": QUORUM_DOMAIN,
                    "binding": "checkpoint-policy",
                    "checkpoint_id": checkpoint_id,
                    "anchor_kind": anchor_kind,
                    "anchor_id": anchor_id,
                    "sequence": int(sequence),
                    "digest": digest,
                    "policy_id": policy_id,
                }
            )
        ).hexdigest()

    def rederived_id(self) -> str:
        return self._derive_id(
            self.checkpoint_id,
            self.anchor_kind,
            self.anchor_id,
            self.sequence,
            self.digest,
            self.policy_id,
        )

    def rederives(self) -> bool:
        return self.binding_id == self.rederived_id()

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "checkpoint_id": self.checkpoint_id,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "digest": self.digest,
            "policy_id": self.policy_id,
            "at": float(self.at),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "CheckpointPolicyBinding":
        if not isinstance(payload, dict):
            raise QuorumStoreError("a checkpoint binding must be an object")

        return cls(
            checkpoint_id=str(payload.get("checkpoint_id", "")),
            anchor_kind=str(payload.get("anchor_kind", "")),
            anchor_id=str(payload.get("anchor_id", "")),
            sequence=int(payload.get("sequence", 0)),
            digest=str(payload.get("digest", "")),
            policy_id=str(payload.get("policy_id", "")),
            binding_id=str(payload.get("binding_id", "")),
            at=float(payload.get("at", 0.0)),
        )


@dataclass(frozen=True)
class QuorumParticipation:
    """One witness's counted vote at one position.

    Kept separately from the receipt set so "which witnesses voted" is a
    question with one answer. The primary key is
    ``(anchor_kind, anchor_id, sequence, witness_id)`` -- a position and an
    identity, not a caller-controlled id -- which is what makes a second
    vote from one witness at one position a *conflict* the store refuses
    rather than a second row nobody notices.
    """

    anchor_kind: str
    anchor_id: str
    sequence: int
    witness_id: str
    receipt_id: str
    digest: str
    checkpoint_id: str
    policy_id: str
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "witness_id": self.witness_id,
            "receipt_id": self.receipt_id,
            "digest": self.digest,
            "checkpoint_id": self.checkpoint_id,
            "policy_id": self.policy_id,
            "at": float(self.at),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "QuorumParticipation":
        if not isinstance(payload, dict):
            raise QuorumStoreError("a participation row must be an object")

        return cls(
            anchor_kind=str(payload.get("anchor_kind", "")),
            anchor_id=str(payload.get("anchor_id", "")),
            sequence=int(payload.get("sequence", 0)),
            witness_id=str(payload.get("witness_id", "")),
            receipt_id=str(payload.get("receipt_id", "")),
            digest=str(payload.get("digest", "")),
            checkpoint_id=str(payload.get("checkpoint_id", "")),
            policy_id=str(payload.get("policy_id", "")),
            at=float(payload.get("at", 0.0)),
        )


@dataclass(frozen=True)
class QuorumDecision:
    """The outcome of one quorum round at one anchor position.

    **A decision is monotone.** Once ``satisfied``, a decision for this
    position never becomes unsatisfied, and the store refuses the write
    that would do it. Quorum is a ratchet: an attacker who can no longer
    reach the threshold must not be able to un-reach a threshold the
    deployment already reached, because "was confirmed" is the fact the
    progression gate is built on.

    ``decision_id`` is derived from the seven things a decision is -- the
    position, the value, the checkpoint, the policy, the threshold, and
    the witnesses counted -- so a persisted decision that disagrees with
    its own fields does not re-derive, and the invariant reports it.
    """

    anchor_kind: str
    anchor_id: str
    sequence: int
    digest: str
    checkpoint_id: str
    policy_id: str
    threshold: int
    witness_ids: tuple[str, ...]
    satisfied: bool
    reason: Optional[str]
    at: float
    decision_id: str = ""

    @classmethod
    def derive(
        cls,
        *,
        anchor_kind: str,
        anchor_id: str,
        sequence: int,
        digest: str,
        checkpoint_id: str,
        policy_id: str,
        threshold: int,
        witness_ids: Any,
        satisfied: bool,
        reason: Optional[str],
        at: float,
    ) -> "QuorumDecision":
        ids = tuple(sorted(str(item) for item in witness_ids))

        return cls(
            anchor_kind=anchor_kind,
            anchor_id=anchor_id,
            sequence=int(sequence),
            digest=digest,
            checkpoint_id=checkpoint_id,
            policy_id=policy_id,
            threshold=int(threshold),
            witness_ids=ids,
            satisfied=bool(satisfied),
            reason=reason,
            at=float(at),
            decision_id=cls._derive_id(
                anchor_kind,
                anchor_id,
                int(sequence),
                digest,
                checkpoint_id,
                policy_id,
                int(threshold),
                ids,
            ),
        )

    @staticmethod
    def _derive_id(
        anchor_kind: str,
        anchor_id: str,
        sequence: int,
        digest: str,
        checkpoint_id: str,
        policy_id: str,
        threshold: int,
        witness_ids: tuple[str, ...],
    ) -> str:
        return hashlib.sha256(
            _canonical_bytes(
                {
                    "domain": QUORUM_DOMAIN,
                    "decision": "quorum",
                    "anchor_kind": anchor_kind,
                    "anchor_id": anchor_id,
                    "sequence": int(sequence),
                    "digest": digest,
                    "checkpoint_id": checkpoint_id,
                    "policy_id": policy_id,
                    "threshold": int(threshold),
                    "witness_ids": list(witness_ids),
                }
            )
        ).hexdigest()

    def rederived_id(self) -> str:
        return self._derive_id(
            self.anchor_kind,
            self.anchor_id,
            self.sequence,
            self.digest,
            self.checkpoint_id,
            self.policy_id,
            self.threshold,
            self.witness_ids,
        )

    def rederives(self) -> bool:
        return self.decision_id == self.rederived_id()

    @property
    def votes(self) -> int:
        return len(self.witness_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "digest": self.digest,
            "checkpoint_id": self.checkpoint_id,
            "policy_id": self.policy_id,
            "threshold": int(self.threshold),
            "witness_ids": list(self.witness_ids),
            "satisfied": bool(self.satisfied),
            "reason": self.reason,
            "at": float(self.at),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "QuorumDecision":
        if not isinstance(payload, dict):
            raise QuorumStoreError("a quorum decision must be an object")

        reason = payload.get("reason")

        return cls(
            anchor_kind=str(payload.get("anchor_kind", "")),
            anchor_id=str(payload.get("anchor_id", "")),
            sequence=int(payload.get("sequence", 0)),
            digest=str(payload.get("digest", "")),
            checkpoint_id=str(payload.get("checkpoint_id", "")),
            policy_id=str(payload.get("policy_id", "")),
            threshold=int(payload.get("threshold", 0)),
            witness_ids=tuple(
                str(item) for item in payload.get("witness_ids", ())
            ),
            satisfied=bool(payload.get("satisfied", False)),
            reason=reason if isinstance(reason, str) else None,
            at=float(payload.get("at", 0.0)),
            decision_id=str(payload.get("decision_id", "")),
        )


@dataclass(frozen=True)
class EquivocationEvidence:
    """Both statements of a witness caught signing two things about one position.

    **This is durable security evidence, not a transient error.** Both
    signed statements are retained in full -- receipts, signatures and all
    -- because the pair is the proof and either half alone is a claim. The
    layer refuses the contradictory vote and stops counting that witness at
    that position, but it does not decide which statement was "really" the
    witness's opinion, because doing so would mean accepting one of two
    mutually contradictory authenticated statements as fact. A witness that
    signed both has told the deployment something more important than
    either digest: that its signature can no longer be read as an opinion
    about one state.

    The evidence is exposed through the SDK and reported by the invariant,
    so an operator learns the witness is unreliable rather than learning
    only that some quorum round failed.
    """

    anchor_kind: str
    anchor_id: str
    sequence: int
    witness_id: str
    first: QuorumReceipt
    second: QuorumReceipt
    detected_at: float
    evidence_id: str = ""

    @classmethod
    def derive(
        cls,
        *,
        first: QuorumReceipt,
        second: QuorumReceipt,
        detected_at: float,
    ) -> "EquivocationEvidence":
        ordered = sorted((first.receipt_id, second.receipt_id))

        return cls(
            anchor_kind=first.anchor_kind,
            anchor_id=first.anchor_id,
            sequence=int(first.sequence),
            witness_id=first.witness_id,
            first=first,
            second=second,
            detected_at=float(detected_at),
            evidence_id=hashlib.sha256(
                _canonical_bytes(
                    {
                        "domain": QUORUM_DOMAIN,
                        "evidence": "equivocation",
                        "anchor_kind": first.anchor_kind,
                        "anchor_id": first.anchor_id,
                        "sequence": int(first.sequence),
                        "witness_id": first.witness_id,
                        "receipts": ordered,
                    }
                )
            ).hexdigest(),
        )

    def statements(self) -> tuple[tuple[str, str], ...]:
        """The two conflicting ``(digest, checkpoint_id)`` pairs."""

        return (self.first.statement, self.second.statement)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "witness_id": self.witness_id,
            "first": self.first.to_dict(),
            "second": self.second.to_dict(),
            "detected_at": float(self.detected_at),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "EquivocationEvidence":
        if not isinstance(payload, dict):
            raise QuorumStoreError(
                "an equivocation record must be an object"
            )

        return cls(
            anchor_kind=str(payload.get("anchor_kind", "")),
            anchor_id=str(payload.get("anchor_id", "")),
            sequence=int(payload.get("sequence", 0)),
            witness_id=str(payload.get("witness_id", "")),
            first=QuorumReceipt.from_dict(payload.get("first")),
            second=QuorumReceipt.from_dict(payload.get("second")),
            detected_at=float(payload.get("detected_at", 0.0)),
            evidence_id=str(payload.get("evidence_id", "")),
        )


@dataclass(frozen=True)
class QuorumStatus:
    """Where one anchor's quorum round stands, right now.

    A read, and a complete one: it says what the round is *about* (the
    bound checkpoint and policy), who has voted, whether the threshold is
    met, whether the round has been confirmed, and -- when the answer is
    "no" -- why. A status that could say "satisfied" without saying what
    was satisfied would be a second authorization path, so the value is
    always carried alongside the verdict.
    """

    anchor_kind: str
    anchor_id: str
    sequence: Optional[int]
    digest: Optional[str]
    checkpoint_id: Optional[str]
    policy_id: Optional[str]
    threshold: int
    witness_ids: tuple[str, ...]
    votes: int
    satisfied: bool
    confirmed: bool
    reason: Optional[str]
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "digest": self.digest,
            "checkpoint_id": self.checkpoint_id,
            "policy_id": self.policy_id,
            "threshold": int(self.threshold),
            "witness_ids": list(self.witness_ids),
            "votes": int(self.votes),
            "satisfied": bool(self.satisfied),
            "confirmed": bool(self.confirmed),
            "reason": self.reason,
            "at": float(self.at),
        }


# =====================================================================
# Journal
# =====================================================================


class WitnessQuorumJournal:
    """The quorum journal: bind a checkpoint, collect receipts, confirm.

    Four operations, and none of them can widen authority.

    ``bind_checkpoint`` ties one v3.4 checkpoint to the policy in force,
    deriving the binding rather than asserting it. ``submit_receipt``
    authenticates one witness's statement and either counts it or refuses
    it by name. ``confirm_quorum`` decides whether the round has been won,
    and refuses -- it does not merely report -- when the witnesses
    disagreed, when one of them equivocated, or when fewer than the
    threshold spoke. ``status`` answers the same question without changing
    anything.

    **Every refusal has a name and every name is a refusal.** Nothing in
    here returns ``True`` where a pre-v3.5 path returned ``False``, and
    :meth:`confirm_quorum` returns a decision rather than raising on an
    ordinary shortfall: not reaching a threshold is a state, not an error,
    and a deployment that has two of three witnesses is not broken -- it is
    below threshold, which is a different thing and worth reporting
    differently.

    **The state is monotonic and the store is durability, not truth.** The
    journal keeps its own account of bindings, receipts, votes, decisions,
    and evidence; a backend failure is a denial rather than an empty
    journal. A persisted row that no longer re-derives to its own id is
    *tampering*, recorded as such and poisoning the anchor it belongs to,
    so a rewritten store yields a refusal instead of a quieter state that
    happens to agree.
    """

    #: The methods that drive the journal. The release's source census
    #: closes over exactly these names in both directions.
    MUTATOR_CALLS: tuple[str, ...] = (
        "register_policy",
        "activate_policy",
        "bind_checkpoint",
        "submit_receipt",
        "confirm_quorum",
        "record_finding",
    )

    def __init__(
        self,
        *,
        clock: Any = None,
        backend: Any = None,
        witness_keys: Optional[Mapping[str, Ed25519PublicKey]] = None,
        policy: Optional[WitnessPolicy] = None,
    ):
        self._clock = clock if clock is not None else time.time
        self._backend = backend

        self._witness_keys: dict[str, Ed25519PublicKey] = {}

        if witness_keys:
            for witness_id, public_key in witness_keys.items():
                self.register_witness_key(witness_id, public_key)

        self._policies: dict[str, WitnessPolicy] = {}
        self._active: Optional[WitnessPolicy] = None
        self._used_policies: set[str] = set()

        self._bindings: dict[str, CheckpointPolicyBinding] = {}
        self._targets: dict[tuple[str, str], CheckpointPolicyBinding] = {}
        self._votes: dict[tuple[str, str, int], dict[str, QuorumReceipt]] = {}
        self._dissent: dict[
            tuple[str, str, int], dict[str, QuorumReceipt]
        ] = {}
        self._statements: dict[tuple[str, str, int, str], QuorumReceipt] = {}
        self._participation: list[QuorumParticipation] = []
        self._receipts: list[QuorumReceipt] = []
        self._decisions: dict[tuple[str, str, int], QuorumDecision] = {}
        self._confirmed: dict[tuple[str, str], QuorumDecision] = {}
        self._evidence: list[EquivocationEvidence] = []
        self._findings: list[QuorumFinding] = []
        self._poisoned: set[tuple[str, str]] = set()
        self._lock = RLock()

        if policy is not None:
            self.register_policy(policy, activate=True)

        if self._backend is not None:
            self._load()

    # ------------------------------------------------------------------
    # Clock and configuration
    # ------------------------------------------------------------------

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock
            return 0.0

    def register_witness_key(
        self,
        witness_id: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        """Register the public half of one witness's key.

        Registration is the whole of this firewall's authority over a
        witness: it cannot tell whether the key really belongs to the
        system the id names, and it does not pretend to. What it can do is
        refuse anything signed by a key nobody registered -- and, more
        importantly, refuse a signature from a key that *is* registered but
        whose identity the active policy does not name.
        """

        if not isinstance(witness_id, str) or not witness_id.strip():
            raise QuorumSignatureError(
                "witness_id must be a non-empty string"
            )

        if not isinstance(public_key, Ed25519PublicKey):
            raise QuorumSignatureError(
                "public_key must be an Ed25519PublicKey"
            )

        self._witness_keys[witness_id] = public_key

    def witness_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._witness_keys))

    def register_policy(
        self,
        policy: Any,
        *,
        activate: bool = False,
    ) -> WitnessPolicy:
        """Register a witness policy, deriving its id from its content.

        A policy whose declared id disagrees with its threshold and witness
        set is refused: it is a claim about a policy rather than a policy,
        and admitting it would let a caller bind checkpoints to the *name*
        of a strong policy while presenting weak fields.

        A policy that is already registered under its derived id and has
        been used is immutable -- a second, different registration under
        the same id is a **policy mutation after use**, refused by name
        rather than applied. A checkpoint already bound under 3-of-5 must
        not silently find itself governed by 2-of-5 because somebody wrote
        a new row with the same id.
        """

        resolved = self._coerce_policy(policy)

        with self._lock:
            existing = self._policies.get(resolved.policy_id)

            if existing is not None:
                if (
                    existing.threshold != resolved.threshold
                    or existing.witness_ids != resolved.witness_ids
                ):
                    self._record(
                        "policy_mismatch",
                        "",
                        "",
                        0,
                        "",
                        resolved.policy_id,
                        "a different policy was presented under an id that "
                        "is already registered and in use",
                    )
                    raise QuorumPolicyError(
                        "a different policy is already registered under this "
                        "id; a policy in use cannot be mutated"
                    )

                if activate:
                    self._activate_locked(resolved)

                return existing

            if self._backend is not None:
                try:
                    self._backend.insert_policy(resolved)
                except QuorumError:
                    raise
                except Exception as exc:  # noqa: BLE001 - a backend failure
                    raise QuorumStoreError(
                        "the quorum store refused the policy: "
                        f"{type(exc).__name__}"
                    ) from exc

            self._policies[resolved.policy_id] = resolved

            if activate:
                self._activate_locked(resolved)

        return resolved

    def activate_policy(self, policy_id: str) -> WitnessPolicy:
        """Make one registered policy the policy in force.

        **The active policy freezes once it has been used.** A binding made
        under 3-of-5 means 3-of-5 governs that checkpoint, and changing the
        policy in force afterwards would be a downgrade dressed as
        configuration: the next checkpoint would be anchored under a weaker
        rule with no discontinuity anywhere in the record. So activating a
        *different* policy after any binding exists is refused, and the
        deployment that genuinely needs a new policy builds a new journal
        -- which is the honest shape of a trust-configuration change.
        """

        if not isinstance(policy_id, str) or not policy_id.strip():
            raise QuorumPolicyError("policy_id must be a non-empty string")

        with self._lock:
            policy = self._policies.get(policy_id)

            if policy is None:
                self._record(
                    "policy_mismatch",
                    "",
                    "",
                    0,
                    "",
                    policy_id,
                    "no registered policy carries this id",
                )
                raise QuorumPolicyError(
                    f"no registered policy carries id {policy_id!r}"
                )

            self._activate_locked(policy)

            return policy

    def _activate_locked(self, policy: WitnessPolicy) -> None:
        current = self._active

        if current is not None and current.policy_id != policy.policy_id:
            if self._used_policies:
                self._record(
                    "policy_mismatch",
                    "",
                    "",
                    0,
                    "",
                    policy.policy_id,
                    "the active policy was already used to bind a "
                    "checkpoint, so it cannot be replaced",
                )
                raise QuorumPolicyError(
                    "the active policy has already bound a checkpoint, so it "
                    "cannot be replaced; a trust-configuration change needs a "
                    "new journal"
                )

        if self._backend is not None:
            try:
                self._backend.set_active_policy(policy.policy_id)
            except QuorumError:
                raise
            except Exception as exc:  # noqa: BLE001 - a backend failure
                raise QuorumStoreError(
                    "the quorum store refused the activation: "
                    f"{type(exc).__name__}"
                ) from exc

        self._active = policy

    @staticmethod
    def _coerce_policy(policy: Any) -> WitnessPolicy:
        if isinstance(policy, WitnessPolicy):
            resolved = policy
        elif isinstance(policy, dict):
            resolved = WitnessPolicy.from_dict(policy)
        else:
            raise QuorumPolicyError(
                "policy must be a WitnessPolicy or an object"
            )

        if not resolved.rederives():
            raise QuorumPolicyError(
                "the policy id does not re-derive from its threshold and "
                "witness set"
            )

        if resolved.threshold > resolved.size:
            raise QuorumPolicyError(
                f"threshold {resolved.threshold} exceeds the "
                f"{resolved.size} witness(es) the policy names"
            )

        return resolved

    def active_policy(self) -> Optional[WitnessPolicy]:
        return self._active

    def policy(self) -> Optional[WitnessPolicy]:
        """The policy in force, or ``None`` when none was configured.

        ``None`` is not an error and not a default: with no policy there is
        no quorum, and every round refuses
        ``anchor_quorum_unconfirmed`` rather than falling back to
        "whoever signed". A deployment that never configured a quorum gets
        a gate it cannot pass, which is the only safe reading of "no
        configuration".
        """

        return self._active

    def policies(self) -> tuple[WitnessPolicy, ...]:
        with self._lock:
            return tuple(
                self._policies[key] for key in sorted(self._policies)
            )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _record(
        self,
        kind: str,
        anchor_kind: Any,
        anchor_id: str,
        sequence: int,
        witness_id: str,
        policy_id: str,
        detail: str,
    ) -> QuorumFinding:
        finding = QuorumFinding(
            kind=kind,
            anchor_kind=(
                anchor_kind.value
                if isinstance(anchor_kind, AnchorKind)
                else str(anchor_kind)
            ),
            anchor_id=str(anchor_id),
            sequence=int(sequence),
            witness_id=str(witness_id),
            policy_id=str(policy_id),
            detail=str(detail),
            at=self._now(),
        )

        with self._lock:
            self._findings.append(finding)

        if self._backend is not None:
            try:
                self._backend.insert_finding(finding)
            except Exception:  # noqa: BLE001 - durability is best-effort
                pass

        return finding

    def record_finding(
        self,
        kind: str,
        *,
        anchor_kind: Any = "",
        anchor_id: str = "",
        sequence: int = 0,
        witness_id: str = "",
        policy_id: str = "",
        detail: str = "",
    ) -> QuorumFinding:
        """Record a refusal by hand, for a caller outside this module.

        Exposed because the SDK records refusals from the progression path,
        where the reason is already known; routing them through the same
        list keeps one account of what was attempted.
        """

        return self._record(
            kind,
            anchor_kind,
            anchor_id,
            sequence,
            witness_id,
            policy_id,
            detail,
        )

    def findings(self) -> tuple[QuorumFinding, ...]:
        with self._lock:
            return tuple(self._findings)

    # ------------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------------

    def bind_checkpoint(
        self,
        checkpoint: Any,
        *,
        policy_id: Optional[str] = None,
    ) -> CheckpointPolicyBinding:
        """Bind one published checkpoint to the policy in force.

        The binding is derived from the checkpoint's own identity and the
        policy's id, so neither can be swapped afterwards. Three refusals,
        in the order that makes each meaningful:

        * **no policy in force** -- there is nothing to bind *to*, and
          inventing one would be the layer choosing its own trust root;
        * **the same checkpoint bound to a different policy** -- a policy
          downgrade arriving at the binding layer, refused rather than
          recorded beside the first binding, because one checkpoint with
          two policies is an ambiguity no quorum can resolve;
        * **a sequence at or below the last confirmed quorum position** --
          the rewind attack, refused before any witness is asked, because
          a witness asked to re-authenticate an old position is a witness
          being used to launder one.
        """

        if isinstance(checkpoint, dict):
            checkpoint = AnchorCheckpoint.from_dict(checkpoint)

        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        with self._lock:
            policy = self._resolve_policy(policy_id)

            self._refuse_if_poisoned(checkpoint.kind, checkpoint.anchor_id)

            existing = self._bindings.get(checkpoint.checkpoint_id)

            binding = CheckpointPolicyBinding.derive(
                checkpoint,
                policy.policy_id,
                at=self._now(),
            )

            if existing is not None:
                if existing.binding_id != binding.binding_id:
                    self._record(
                        "policy_mismatch",
                        checkpoint.kind,
                        checkpoint.anchor_id,
                        checkpoint.sequence,
                        "",
                        policy.policy_id,
                        "this checkpoint is already bound to a different "
                        "policy, so it cannot be re-bound",
                    )
                    raise QuorumPolicyError(
                        "this checkpoint is already bound to a different "
                        "policy; a checkpoint holds exactly one binding"
                    )

                return existing

            key = (checkpoint.kind.value, checkpoint.anchor_id)
            last = self._confirmed.get(key)

            if last is not None and int(checkpoint.sequence) <= int(
                last.sequence
            ):
                self._record(
                    "witness_stale",
                    checkpoint.kind,
                    checkpoint.anchor_id,
                    checkpoint.sequence,
                    "",
                    policy.policy_id,
                    f"quorum is already confirmed at sequence "
                    f"{last.sequence}, so a checkpoint at "
                    f"{checkpoint.sequence} cannot be bound",
                )
                raise QuorumStaleReceiptError(
                    f"quorum is already confirmed at sequence "
                    f"{last.sequence} for this anchor"
                )

            if self._backend is not None:
                try:
                    self._backend.insert_binding(binding)
                except QuorumError:
                    raise
                except Exception as exc:  # noqa: BLE001 - a backend failure
                    raise QuorumStoreError(
                        "the quorum store refused the binding: "
                        f"{type(exc).__name__}"
                    ) from exc

            self._bindings[binding.checkpoint_id] = binding
            self._targets[key] = binding
            self._used_policies.add(policy.policy_id)

        return binding

    def _resolve_policy(
        self,
        policy_id: Optional[str],
    ) -> WitnessPolicy:
        if policy_id is not None:
            policy = self._policies.get(policy_id)

            if policy is None:
                raise QuorumPolicyError(
                    f"no registered policy carries id {policy_id!r}"
                )

            return policy

        policy = self._active

        if policy is None:
            self._record(
                "policy_mismatch",
                "",
                "",
                0,
                "",
                str(policy_id or ""),
                "no witness policy is in force, so nothing can be bound",
            )
            raise QuorumPolicyError(
                "no witness policy is in force, so a checkpoint cannot be "
                "bound"
            )

        return policy

    def target(
        self,
        kind: Any,
        anchor_id: str,
    ) -> Optional[CheckpointPolicyBinding]:
        """The checkpoint this anchor's current round is bound to."""

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return None

        with self._lock:
            return self._targets.get((resolved.value, anchor_id))

    def bindings(self) -> tuple[CheckpointPolicyBinding, ...]:
        with self._lock:
            return tuple(
                self._bindings[key] for key in sorted(self._bindings)
            )

    # ------------------------------------------------------------------
    # Receipts
    # ------------------------------------------------------------------

    def verify_receipt(self, receipt: Any) -> bool:
        """Whether a receipt re-derives and verifies under a registered key.

        The predicate the invariant asks of every stored row: a receipt that
        does not re-derive to its own id, or whose signature does not
        verify under the key registered for the witness it names, is
        evidence of nothing.
        """

        if not isinstance(receipt, QuorumReceipt):
            return False

        if not receipt.rederives():
            return False

        public_key = self._witness_keys.get(receipt.witness_id)

        if public_key is None:
            return False

        return verify_receipt_signature(receipt, public_key)

    def submit_receipt(self, receipt: Any) -> QuorumReceipt:
        """Authenticate one witness's statement, and count it or refuse it.

        The order of the checks is the design. Each one is a property the
        next assumes, so a receipt that fails an early check is never
        quietly interpreted by a later one:

        1. **it re-derives** -- or it is not the bytes a witness signed;
        2. **the witness is trusted** -- registered, *and* named by the
           policy in force. A valid signature from an untrusted identity is
           worth exactly nothing, and admitting it would let an attacker
           who holds any registered key vote on any anchor;
        3. **the signature verifies**;
        4. **the witness has not already said something different here** --
           equivocation, which is recorded as evidence and refuses;
        5. **the anchor has a bound checkpoint at this position** -- or the
           receipt is about an anchor the deployment never anchored;
        6. **the position is current** -- a receipt for a position quorum
           has moved past is stale, even if it is genuine;
        7. **the statement matches the binding exactly** -- same digest,
           same checkpoint, same policy. A trusted witness saying something
           *different* about this position is dissent, and dissent is
           recorded rather than dropped: witnesses disagreeing is the most
           important fact a quorum can learn;
        8. **the witness has not already voted** -- a second vote from one
           identity is refused, whether it repeats the first (a duplicate)
           or contradicts it (step 4).

        Nothing that is refused is counted, and nothing that is refused is
        discarded silently: every refusal is a named finding.
        """

        if isinstance(receipt, dict):
            receipt = QuorumReceipt.from_dict(receipt)

        if not isinstance(receipt, QuorumReceipt):
            raise TypeError("receipt must be a QuorumReceipt")

        with self._lock:
            policy = self._active

            # 1. Structural integrity.
            if not receipt.rederives():
                self._record(
                    "witness_invalid_signature",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    "the receipt id does not re-derive from its own fields",
                )
                raise QuorumSignatureError(
                    "the receipt id does not re-derive from its own fields"
                )

            self._refuse_if_poisoned_name(
                receipt.anchor_kind,
                receipt.anchor_id,
            )

            # 2. Trust. Both halves: a registered key, and an identity the
            # policy in force names.
            if policy is None:
                self._record(
                    "witness_untrusted",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    "no witness policy is in force, so no witness is trusted",
                )
                raise QuorumUntrustedWitnessError(
                    "no witness policy is in force, so no witness is trusted"
                )

            if not policy.trusts(receipt.witness_id):
                self._record(
                    "witness_untrusted",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"witness {receipt.witness_id!r} is not named by the "
                    "active policy",
                )
                raise QuorumUntrustedWitnessError(
                    f"witness {receipt.witness_id!r} is not named by the "
                    "active policy"
                )

            if self._witness_keys.get(receipt.witness_id) is None:
                self._record(
                    "witness_untrusted",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"no key is registered for witness "
                    f"{receipt.witness_id!r}",
                )
                raise QuorumUntrustedWitnessError(
                    f"no key is registered for witness "
                    f"{receipt.witness_id!r}"
                )

            # 3. Signature.
            if not verify_receipt_signature(
                receipt,
                self._witness_keys[receipt.witness_id],
            ):
                self._record(
                    "witness_invalid_signature",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    "the signature does not verify under the registered key",
                )
                raise QuorumSignatureError(
                    "the receipt's signature does not verify"
                )

            # 4. Equivocation. Checked *before* the target is consulted, so
            # a witness that contradicts itself is caught even when the
            # position has moved on and a later check would otherwise
            # refuse it for a duller reason.
            statement_key = receipt.position + (receipt.witness_id,)
            previous = self._statements.get(statement_key)

            if previous is not None and previous.statement != receipt.statement:
                self._record_equivocation(previous, receipt)
                raise QuorumEquivocationError(
                    f"witness {receipt.witness_id!r} already signed a "
                    f"different digest for this anchor at sequence "
                    f"{receipt.sequence}; both statements are retained "
                    "as evidence and neither is counted"
                )

            # 5. The anchor has a bound checkpoint at all.
            key = (receipt.anchor_kind, receipt.anchor_id)
            target = self._targets.get(key)

            if target is None:
                self._record(
                    "checkpoint_mismatch",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    "no checkpoint is bound for this anchor, so there is no "
                    "round to vote in",
                )
                raise QuorumCheckpointMismatchError(
                    "no checkpoint is bound for this anchor, so there is no "
                    "quorum round to vote in"
                )

            # 6. Currency.
            if int(receipt.sequence) < int(target.sequence):
                self._record(
                    "witness_stale",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"the anchor is bound at sequence {target.sequence}, so "
                    f"a receipt at {receipt.sequence} is stale",
                )
                raise QuorumStaleReceiptError(
                    f"the anchor is bound at sequence {target.sequence}; a "
                    f"receipt at {receipt.sequence} describes a position "
                    "this anchor has moved past"
                )

            if int(receipt.sequence) > int(target.sequence):
                self._record(
                    "checkpoint_mismatch",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"the anchor is bound at sequence {target.sequence}, so "
                    f"a receipt at {receipt.sequence} describes a position "
                    "that was never anchored",
                )
                raise QuorumCheckpointMismatchError(
                    f"the anchor is bound at sequence {target.sequence}; a "
                    f"receipt at {receipt.sequence} describes a position "
                    "that was never anchored"
                )

            # 7. Agreement on the statement and the policy. A trusted
            # witness saying something different is *dissent*, and dissent
            # is the one outcome a quorum must never paper over.
            if receipt.policy_id != target.policy_id:
                self._record_dissent(receipt, target)
                self._record(
                    "policy_mismatch",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"the anchor is bound under policy "
                    f"{target.policy_id[:8]}... but the receipt was signed "
                    f"under {receipt.policy_id[:8]}...",
                )
                raise QuorumPolicyError(
                    "the receipt was signed under a policy this checkpoint "
                    "is not bound to"
                )

            if (
                receipt.digest != target.digest
                or receipt.checkpoint_id != target.checkpoint_id
            ):
                self._record_dissent(receipt, target)
                self._record(
                    "checkpoint_mismatch",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    "a trusted witness authenticated a different value for "
                    "this anchor position",
                )
                raise QuorumCheckpointMismatchError(
                    "the receipt authenticates a different value for this "
                    "anchor position than the checkpoint it is bound to"
                )

            # 8. One witness, one vote. The same-statement case, which can
            # only be recognised once the receipt is known to agree with
            # the binding -- a receipt that disagrees was already refused
            # above as dissent or a policy mismatch, and labelling it a
            # duplicate would hide what the witness actually said.
            round_key = receipt.position
            votes = self._votes.setdefault(round_key, {})

            if previous is not None and (
                previous.receipt_id == receipt.receipt_id
            ):
                # Idempotent replay of one receipt: not a second vote and
                # not an error. A retried submission -- a crashed client, a
                # duplicated network delivery -- must not change the count
                # in either direction.
                return previous

            if receipt.witness_id in votes:
                self._record(
                    "witness_duplicate",
                    receipt.anchor_kind,
                    receipt.anchor_id,
                    receipt.sequence,
                    receipt.witness_id,
                    receipt.policy_id,
                    f"witness {receipt.witness_id!r} already voted in this "
                    "round",
                )
                raise QuorumDuplicateWitnessError(
                    f"witness {receipt.witness_id!r} has already voted in "
                    "this round; one witness casts one vote"
                )

            if self._backend is not None:
                try:
                    self._backend.insert_receipt(receipt)
                    self._backend.insert_participation(
                        QuorumParticipation(
                            anchor_kind=receipt.anchor_kind,
                            anchor_id=receipt.anchor_id,
                            sequence=int(receipt.sequence),
                            witness_id=receipt.witness_id,
                            receipt_id=receipt.receipt_id,
                            digest=receipt.digest,
                            checkpoint_id=receipt.checkpoint_id,
                            policy_id=receipt.policy_id,
                            at=self._now(),
                        )
                    )
                except QuorumError:
                    raise
                except Exception as exc:  # noqa: BLE001 - a backend failure
                    raise QuorumStoreError(
                        "the quorum store refused the receipt: "
                        f"{type(exc).__name__}"
                    ) from exc

            votes[receipt.witness_id] = receipt
            self._statements[statement_key] = receipt
            self._receipts.append(receipt)
            self._participation.append(
                QuorumParticipation(
                    anchor_kind=receipt.anchor_kind,
                    anchor_id=receipt.anchor_id,
                    sequence=int(receipt.sequence),
                    witness_id=receipt.witness_id,
                    receipt_id=receipt.receipt_id,
                    digest=receipt.digest,
                    checkpoint_id=receipt.checkpoint_id,
                    policy_id=receipt.policy_id,
                    at=self._now(),
                )
            )

        return receipt

    def _record_dissent(
        self,
        receipt: QuorumReceipt,
        target: CheckpointPolicyBinding,
    ) -> None:
        """Remember that a trusted witness said something else here.

        A dissenting statement is not counted and is not discarded: it is
        the evidence that the witnesses do not agree about this anchor
        position, which is a stronger fact than any count. The round is
        marked split the moment dissent exists, and no threshold of
        agreeing witnesses can confirm over it.
        """

        self._dissent.setdefault(receipt.position, {})[
            receipt.witness_id
        ] = receipt

    def _record_equivocation(
        self,
        first: QuorumReceipt,
        second: QuorumReceipt,
    ) -> EquivocationEvidence:
        evidence = EquivocationEvidence.derive(
            first=first,
            second=second,
            detected_at=self._now(),
        )

        self._evidence.append(evidence)

        # The equivocating witness stops counting at this position. Both
        # statements are retained, so nothing is destroyed and nothing is
        # chosen; only the *vote* is withdrawn.
        self._votes.get(second.position, {}).pop(second.witness_id, None)
        self._dissent.get(second.position, {}).pop(second.witness_id, None)

        self._record(
            "witness_equivocation",
            second.anchor_kind,
            second.anchor_id,
            second.sequence,
            second.witness_id,
            second.policy_id,
            f"witness {second.witness_id!r} signed two different digests "
            f"for this position ({first.digest[:8]}... and "
            f"{second.digest[:8]}...); both are retained as evidence and "
            "neither is counted",
        )

        if self._backend is not None:
            try:
                self._backend.insert_equivocation(evidence)
            except Exception as exc:  # noqa: BLE001 - a backend failure
                raise QuorumStoreError(
                    "the quorum store refused the equivocation evidence: "
                    f"{type(exc).__name__}"
                ) from exc

        return evidence

    def receipts(self) -> tuple[QuorumReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def participation(self) -> tuple[QuorumParticipation, ...]:
        with self._lock:
            return tuple(self._participation)

    def votes(
        self,
        kind: Any,
        anchor_id: str,
        sequence: Optional[int] = None,
    ) -> tuple[QuorumReceipt, ...]:
        """The counted votes at one anchor position, sorted by witness.

        Counted, not merely submitted: a refused vote is not in here, which
        is what makes "duplicate witnesses cannot add votes" a fact about
        the state rather than a promise in a docstring.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return ()

        with self._lock:
            if sequence is None:
                target = self._targets.get((resolved.value, anchor_id))

                if target is None:
                    return ()

                sequence = target.sequence

            round_key = (resolved.value, anchor_id, int(sequence))
            votes = self._votes.get(round_key, {})

            return tuple(
                votes[key] for key in sorted(votes)
            )

    def dissent(
        self,
        kind: Any,
        anchor_id: str,
        sequence: Optional[int] = None,
    ) -> tuple[QuorumReceipt, ...]:
        """Statements by trusted witnesses that contradict the binding."""

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return ()

        with self._lock:
            if sequence is None:
                target = self._targets.get((resolved.value, anchor_id))

                if target is None:
                    return ()

                sequence = target.sequence

            entries = self._dissent.get(
                (resolved.value, anchor_id, int(sequence)),
                {},
            )

            return tuple(entries[key] for key in sorted(entries))

    def equivocations(self) -> tuple[EquivocationEvidence, ...]:
        with self._lock:
            return tuple(self._evidence)

    # ------------------------------------------------------------------
    # Confirmation
    # ------------------------------------------------------------------

    def confirm_quorum(
        self,
        kind: Any,
        anchor_id: str,
    ) -> QuorumDecision:
        """Decide whether this anchor's round has been won.

        Returns a decision rather than a boolean, because a round that was
        not won is a state a deployment has to reason about, and the reason
        is the part that matters: *insufficient* says get more witnesses,
        *split* says the witnesses disagree and no number of additional
        signatures fixes that, *unverifiable* says the state this decision
        would rest on cannot be trusted.

        Three ways to lose, checked in this order:

        * **unverifiable** -- the persisted quorum state for this anchor
          does not re-derive, so there is nothing to decide with;
        * **split** -- a trusted witness authenticated a *different* value
          for this position. This is refused even when the threshold of
          agreeing witnesses is present, because a quorum that confirmed
          over dissent would be reporting agreement that does not exist;
        * **insufficient** -- fewer distinct trusted witnesses voted than
          the policy requires.

        Confirmation is monotone: a position that has been confirmed stays
        confirmed, and a later call cannot un-confirm it. The ratchet is
        the point -- an attacker who loses a witness must not be able to
        take back a confirmation the deployment already relied on.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None:
            raise QuorumUnconfirmedError(f"unknown anchor kind: {kind!r}")

        if not isinstance(anchor_id, str) or not anchor_id.strip():
            raise QuorumUnconfirmedError(
                "anchor_id must be a non-empty string"
            )

        with self._lock:
            key = (resolved.value, anchor_id)
            target = self._targets.get(key)

            if target is None:
                self._record(
                    "quorum_insufficient",
                    resolved,
                    anchor_id,
                    0,
                    "",
                    "",
                    "no checkpoint is bound for this anchor, so there is no "
                    "round to confirm",
                )
                return QuorumDecision.derive(
                    anchor_kind=resolved.value,
                    anchor_id=anchor_id,
                    sequence=0,
                    digest="",
                    checkpoint_id="",
                    policy_id="",
                    threshold=0,
                    witness_ids=(),
                    satisfied=False,
                    reason="anchor_quorum_unconfirmed",
                    at=self._now(),
                )

            if key in self._poisoned:
                self._record(
                    "unverifiable",
                    resolved,
                    anchor_id,
                    target.sequence,
                    "",
                    target.policy_id,
                    "the persisted quorum state for this anchor does not "
                    "re-derive, so it cannot be confirmed",
                )
                return QuorumDecision.derive(
                    anchor_kind=resolved.value,
                    anchor_id=anchor_id,
                    sequence=target.sequence,
                    digest=target.digest,
                    checkpoint_id=target.checkpoint_id,
                    policy_id=target.policy_id,
                    threshold=self._threshold_locked(target),
                    witness_ids=(),
                    satisfied=False,
                    reason="anchor_quorum_unverifiable",
                    at=self._now(),
                )

            round_key = (resolved.value, anchor_id, int(target.sequence))
            existing = self._decisions.get(round_key)

            # Monotonic: a confirmed position is never re-decided. Re-run
            # the counting and a deployment that lost a witness would watch
            # its own confirmation disappear.
            if existing is not None and existing.satisfied:
                return existing

            policy = self._policies.get(target.policy_id)

            if policy is None:
                self._record(
                    "policy_mismatch",
                    resolved,
                    anchor_id,
                    target.sequence,
                    "",
                    target.policy_id,
                    "the bound policy is not registered, so the threshold "
                    "is unknown",
                )
                return QuorumDecision.derive(
                    anchor_kind=resolved.value,
                    anchor_id=anchor_id,
                    sequence=target.sequence,
                    digest=target.digest,
                    checkpoint_id=target.checkpoint_id,
                    policy_id=target.policy_id,
                    threshold=0,
                    witness_ids=(),
                    satisfied=False,
                    reason="anchor_policy_mismatch",
                    at=self._now(),
                )

            votes = self._votes.get(round_key, {})
            dissent = self._dissent.get(round_key, {})

            counted = {
                witness_id: receipt
                for witness_id, receipt in votes.items()
                if policy.trusts(witness_id)
            }

            if dissent:
                self._record(
                    "quorum_split",
                    resolved,
                    anchor_id,
                    target.sequence,
                    "",
                    target.policy_id,
                    "trusted witnesses authenticated conflicting values for "
                    f"this position ({len(dissent)} dissenting: "
                    + ", ".join(sorted(dissent))
                    + "), so the round cannot be confirmed at any threshold",
                )
                decision = QuorumDecision.derive(
                    anchor_kind=resolved.value,
                    anchor_id=anchor_id,
                    sequence=target.sequence,
                    digest=target.digest,
                    checkpoint_id=target.checkpoint_id,
                    policy_id=target.policy_id,
                    threshold=policy.threshold,
                    witness_ids=tuple(sorted(counted)),
                    satisfied=False,
                    reason="anchor_quorum_split",
                    at=self._now(),
                )
                self._store_decision(decision, round_key, key)
                return decision

            satisfied = len(counted) >= int(policy.threshold)

            if not satisfied:
                self._record(
                    "quorum_insufficient",
                    resolved,
                    anchor_id,
                    target.sequence,
                    "",
                    target.policy_id,
                    f"{len(counted)} distinct trusted witness(es) voted and "
                    f"the policy requires {policy.threshold}",
                )

            decision = QuorumDecision.derive(
                anchor_kind=resolved.value,
                anchor_id=anchor_id,
                sequence=target.sequence,
                digest=target.digest,
                checkpoint_id=target.checkpoint_id,
                policy_id=target.policy_id,
                threshold=policy.threshold,
                witness_ids=tuple(sorted(counted)),
                satisfied=satisfied,
                reason=(
                    None
                    if satisfied
                    else "anchor_quorum_insufficient"
                ),
                at=self._now(),
            )

            self._store_decision(decision, round_key, key)

            return decision

    def _threshold_locked(
        self,
        target: CheckpointPolicyBinding,
    ) -> int:
        policy = self._policies.get(target.policy_id)

        return 0 if policy is None else int(policy.threshold)

    def _store_decision(
        self,
        decision: QuorumDecision,
        round_key: tuple[str, str, int],
        anchor_key: tuple[str, str],
    ) -> None:
        self._decisions[round_key] = decision

        if decision.satisfied:
            current = self._confirmed.get(anchor_key)

            if current is None or int(decision.sequence) > int(
                current.sequence
            ):
                self._confirmed[anchor_key] = decision

        if self._backend is not None:
            try:
                self._backend.insert_decision(decision)
            except QuorumError:
                raise
            except Exception as exc:  # noqa: BLE001 - a backend failure
                raise QuorumStoreError(
                    "the quorum store refused the decision: "
                    f"{type(exc).__name__}"
                ) from exc

    def status(
        self,
        kind: Any,
        anchor_id: str,
    ) -> QuorumStatus:
        """Where this anchor's round stands, without changing anything.

        The same counting :meth:`confirm_quorum` performs, reported rather
        than recorded. It answers the three questions a deployment
        actually has -- what is the round about, who has voted, and why is
        it not confirmed yet -- and it never flips a decision, so a caller
        can poll it without participating in the outcome.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return QuorumStatus(
                anchor_kind=str(kind),
                anchor_id=str(anchor_id),
                sequence=None,
                digest=None,
                checkpoint_id=None,
                policy_id=None,
                threshold=0,
                witness_ids=(),
                votes=0,
                satisfied=False,
                confirmed=False,
                reason="anchor_quorum_unconfirmed",
                at=self._now(),
            )

        with self._lock:
            key = (resolved.value, anchor_id)
            target = self._targets.get(key)

            if target is None:
                return QuorumStatus(
                    anchor_kind=resolved.value,
                    anchor_id=anchor_id,
                    sequence=None,
                    digest=None,
                    checkpoint_id=None,
                    policy_id=None,
                    threshold=0,
                    witness_ids=(),
                    votes=0,
                    satisfied=False,
                    confirmed=False,
                    reason="anchor_quorum_unconfirmed",
                    at=self._now(),
                )

            policy = self._policies.get(target.policy_id)
            threshold = 0 if policy is None else int(policy.threshold)

            round_key = (resolved.value, anchor_id, int(target.sequence))
            votes = self._votes.get(round_key, {})
            dissent = self._dissent.get(round_key, {})
            counted = tuple(sorted(votes))
            decision = self._decisions.get(round_key)
            confirmed = self._confirmed.get(key)

            satisfied = bool(decision is not None and decision.satisfied)

            if key in self._poisoned:
                reason: Optional[str] = "anchor_quorum_unverifiable"
            elif dissent:
                reason = "anchor_quorum_split"
            elif policy is None:
                reason = "anchor_policy_mismatch"
            elif satisfied:
                reason = None
            else:
                reason = "anchor_quorum_insufficient"

            return QuorumStatus(
                anchor_kind=resolved.value,
                anchor_id=anchor_id,
                sequence=int(target.sequence),
                digest=target.digest,
                checkpoint_id=target.checkpoint_id,
                policy_id=target.policy_id,
                threshold=threshold,
                witness_ids=counted,
                votes=len(counted),
                satisfied=satisfied,
                confirmed=bool(
                    confirmed is not None
                    and int(confirmed.sequence) == int(target.sequence)
                ),
                reason=reason,
                at=self._now(),
            )

    def confirmed(
        self,
        kind: Any,
        anchor_id: str,
    ) -> Optional[QuorumDecision]:
        """The latest confirmed decision for one anchor, or ``None``."""

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return None

        with self._lock:
            return self._confirmed.get((resolved.value, anchor_id))

    def decisions(self) -> tuple[QuorumDecision, ...]:
        with self._lock:
            return tuple(
                self._decisions[key] for key in sorted(self._decisions)
            )

    def poisoned(self) -> tuple[tuple[str, str], ...]:
        """Anchors whose persisted state no longer re-derives."""

        with self._lock:
            return tuple(sorted(self._poisoned))

    def _refuse_if_poisoned(
        self,
        kind: AnchorKind,
        anchor_id: str,
    ) -> None:
        self._refuse_if_poisoned_name(kind.value, anchor_id)

    def _refuse_if_poisoned_name(
        self,
        anchor_kind: str,
        anchor_id: str,
    ) -> None:
        if (anchor_kind, anchor_id) in self._poisoned:
            self._record(
                "unverifiable",
                anchor_kind,
                anchor_id,
                0,
                "",
                "",
                "the persisted quorum state for this anchor does not "
                "re-derive, so it is refused",
            )
            raise QuorumStoreError(
                "the persisted quorum state for this anchor does not "
                "re-derive, so the operation is refused"
            )

    # ------------------------------------------------------------------
    # Durability
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Rehydrate from the backend, poisoning anything that fails.

        A persisted row that no longer re-derives to its own id is not a
        row this journal may use. It is *tampering* where the layer can
        tell the difference -- a rewritten digest, a decision whose
        threshold was edited, a participation row that claims a witness
        voted when the receipt does not verify -- and the response is to
        record it and poison the anchor, so the deployment refuses rather
        than reasoning over state that has been edited behind its back.

        An unreadable backend is a denial at construction, never an empty
        journal: "I could not read the confirmed set" and "there is no
        confirmed set" are different statements, and only one is safe.
        """

        try:
            policies = tuple(self._backend.load_policies())
            bindings = tuple(self._backend.load_bindings())
            receipts = tuple(self._backend.load_receipts())
            decisions = tuple(self._backend.load_decisions())
            participation = tuple(self._backend.load_participation())
            evidence = tuple(self._backend.load_equivocation())
            findings = tuple(self._backend.load_findings())
            active = self._backend.active_policy_id()
        except Exception as exc:  # noqa: BLE001 - unreadable state
            raise QuorumStoreError(
                "the quorum store could not be read at construction"
            ) from exc

        # Rows the store held back because their two accounts of themselves
        # disagreed. Each one poisons the anchor it names, so a rewritten
        # store refuses rather than serving a quieter state that happens to
        # agree.
        try:
            quarantine = tuple(self._backend.quarantine())
        except Exception:  # noqa: BLE001 - an unreadable quarantine
            quarantine = (
                ("", "", "the quorum store's quarantine could not be read"),
            )

        with self._lock:
            for anchor_kind, anchor_id, detail in quarantine:
                if anchor_kind and anchor_id:
                    self._poison(anchor_kind, anchor_id)
                else:
                    self._findings.append(
                        QuorumFinding(
                            kind="tampered",
                            anchor_kind=anchor_kind,
                            anchor_id=anchor_id,
                            sequence=0,
                            witness_id="",
                            policy_id="",
                            detail=detail,
                            at=self._now(),
                        )
                    )

            for policy in policies:
                if not isinstance(policy, WitnessPolicy):
                    continue

                if policy.rederives():
                    self._policies[policy.policy_id] = policy
                else:
                    self._findings.append(
                        QuorumFinding(
                            kind="tampered",
                            anchor_kind="",
                            anchor_id="",
                            sequence=0,
                            witness_id="",
                            policy_id=str(policy.policy_id),
                            detail=(
                                "a persisted witness policy does not "
                                "re-derive to its stored id"
                            ),
                            at=self._now(),
                        )
                    )

            if active:
                self._active = self._policies.get(active)

            for binding in bindings:
                if not isinstance(binding, CheckpointPolicyBinding):
                    continue

                if not binding.rederives():
                    self._poison(binding.anchor_kind, binding.anchor_id)
                    continue

                self._bindings[binding.checkpoint_id] = binding
                self._targets[
                    (binding.anchor_kind, binding.anchor_id)
                ] = binding
                self._used_policies.add(binding.policy_id)

            for receipt in receipts:
                if not isinstance(receipt, QuorumReceipt):
                    continue

                if not receipt.rederives():
                    self._poison(receipt.anchor_kind, receipt.anchor_id)
                    continue

                self._receipts.append(receipt)
                self._statements[
                    receipt.position + (receipt.witness_id,)
                ] = receipt
                self._votes.setdefault(receipt.position, {}).setdefault(
                    receipt.witness_id,
                    receipt,
                )

            for row in participation:
                if not isinstance(row, QuorumParticipation):
                    continue

                self._participation.append(row)

            for decision in decisions:
                if not isinstance(decision, QuorumDecision):
                    continue

                round_key = (
                    decision.anchor_kind,
                    decision.anchor_id,
                    int(decision.sequence),
                )

                if not decision.rederives():
                    self._poison(decision.anchor_kind, decision.anchor_id)
                    continue

                self._decisions[round_key] = decision

                if decision.satisfied:
                    anchor_key = (decision.anchor_kind, decision.anchor_id)
                    current = self._confirmed.get(anchor_key)

                    if current is None or int(decision.sequence) > int(
                        current.sequence
                    ):
                        self._confirmed[anchor_key] = decision

            for item in evidence:
                if not isinstance(item, EquivocationEvidence):
                    continue

                self._evidence.append(item)

                # An equivocating witness stops counting at that position,
                # and that has to survive a restart: the store keeps the
                # first statement because it was genuinely signed and the
                # count was only withdrawn afterwards, so rehydrating
                # naively would hand the witness its vote back.
                self._votes.get(
                    (item.anchor_kind, item.anchor_id, int(item.sequence)),
                    {},
                ).pop(item.witness_id, None)

            for finding in findings:
                if isinstance(finding, QuorumFinding):
                    self._findings.append(finding)

    def _poison(self, anchor_kind: str, anchor_id: str) -> None:
        self._poisoned.add((anchor_kind, anchor_id))
        self._findings.append(
            QuorumFinding(
                kind="tampered",
                anchor_kind=anchor_kind,
                anchor_id=anchor_id,
                sequence=0,
                witness_id="",
                policy_id="",
                detail=(
                    "persisted quorum state for this anchor does not "
                    "re-derive to its stored id"
                ),
                at=self._now(),
            )
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def size(self) -> int:
        with self._lock:
            return len(self._receipts)

    def round_count(self) -> int:
        with self._lock:
            return len(self._decisions)


__all__ = [
    "QUORUM_DOMAIN",
    "QUORUM_FINDING_KINDS",
    "SUPPORTED_QUORUM_ALGORITHMS",
    "CheckpointPolicyBinding",
    "EquivocationEvidence",
    "InProcessQuorumWitness",
    "QuorumCheckpointMismatchError",
    "QuorumDecision",
    "QuorumDuplicateWitnessError",
    "QuorumEquivocationError",
    "QuorumError",
    "QuorumFinding",
    "QuorumInsufficientError",
    "QuorumParticipation",
    "QuorumPolicyError",
    "QuorumReceipt",
    "QuorumSignatureError",
    "QuorumSplitError",
    "QuorumStaleReceiptError",
    "QuorumStatus",
    "QuorumStoreError",
    "QuorumUnconfirmedError",
    "QuorumUntrustedWitnessError",
    "QuorumWitness",
    "WitnessPolicy",
    "WitnessQuorumJournal",
    "verify_receipt_signature",
]
