"""External anchoring: binding a local trust root to something outside.

Every earlier layer in this package raised the cost of tampering and then,
in its honest-non-guarantees list, admitted the same thing: the *root* of
trust stayed inside the process. The lineage chain head is a row in the
lineage store. The temporal watermark is a row in the watermark store. The
issuer trust registry is a row in the issuer store. A hash chain whose head
sits next to the chain proves the chain is internally consistent; it does
not prove the chain is the one that was built, because the only thing
separating a real history from a fabricated one is a digest the same process
also writes.

This module adds the missing half. An **anchor** is a value that, if an
attacker can write it, silently makes every check above it pass. A
**checkpoint** is a statement about one anchor at one instant, signed by a
key the firewall does not hold. A **witness** is whatever holds those
checkpoints outside the firewall's storage. The property is the whole
design:

    a trust root the firewall holds is not a root of trust.

Nothing here can widen authority, and the release's invariant checks that
in both directions. Every verdict this module produces is a *refusal*: an
anchor that disagrees with the last confirmed checkpoint does not progress,
and no code path in the layer returns ``True`` where a pre-v3.4 path
returned ``False``. ``FirewallSDK.authorize()`` remains the only allow
origin, and no ALLOW-path function references anchor state at all.

**What a checkpoint buys, and what it does not.** The signature proves *who*
said the head was X. The monotone ``sequence`` proves *when in the anchor's
life* they said it, which is what turns "the head is X" into "the head was X
and has not gone backwards". A witness that signs whatever it is handed
attests nothing; the layer's security is exactly the security of the
witness's own key management, which this package does not own and does not
pretend to.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Domain separator, so a digest computed here can never be confused with a
#: digest computed by any other layer of this package.
ANCHOR_DOMAIN = "agent-firewall/external-anchor/v1"

#: The signing algorithm this module can verify. Anything else is refused,
#: because "an algorithm I do not implement" must not be a way in.
SUPPORTED_ALGORITHMS = ("Ed25519",)


class AnchorKind(str, Enum):
    """The three anchors this package reads on a progression path.

    They are not the same shape and this module does not pretend they are:
    the lineage head is a monotone sequence with a digest, the watermark is a
    high-water mark on two clocks, the issuer registry is a set of keys with
    revocations. What they share is the property that matters -- each is a
    value that, if an attacker can write it, silently makes every check above
    it pass.
    """

    LINEAGE_HEAD = "lineage_head"
    TEMPORAL_WATERMARK = "temporal_watermark"
    ISSUER_REGISTRY = "issuer_registry"


def anchor_kind_of(value: Any) -> Optional[AnchorKind]:
    """Coerce a value to an :class:`AnchorKind`, or ``None``.

    ``None`` rather than an exception because every caller here is deciding
    whether it recognizes something, and an unrecognized label must degrade
    to *unknown* rather than to the permissive end.
    """

    if isinstance(value, AnchorKind):
        return value

    if isinstance(value, str):
        try:
            return AnchorKind(value)
        except ValueError:
            return None

    return None


#: Reads one anchor's current ``(sequence, digest)``, or ``None`` when the
#: anchor does not exist. Supplied by whoever owns the store, so this module
#: never reaches into another layer's storage itself.
AnchorReader = Callable[[str], Optional[tuple[int, str]]]

#: Reads the digest one anchor committed to *at* a given sequence, or
#: ``None`` when the anchor has no position there.
#:
#: A second reader rather than a richer first one, because the two answer
#: different questions and only one of them can be answered from the head.
#: ``AnchorReader`` says where the anchor is now; this says what it committed
#: to at a position it has since moved past. Without it, ``compare`` could
#: only ever check the confirmed checkpoint against a head that happened to
#: sit at the same sequence -- and a fabricated chain *longer* than the
#: confirmed one would present a head at a higher sequence and never be
#: compared against anything at all.
AnchorPrefixReader = Callable[[str, int], Optional[str]]


def _canonical_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding of a signed or digested structure.

    One encoding for every digest and every signature here, so a value that
    re-derives to a digest on one side re-derives to the same digest on the
    other. ``sort_keys`` makes the byte string independent of insertion
    order and the compact separators make it independent of whitespace --
    the two classic ways a "signature mismatch" turns out to be an encoding
    mismatch.
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
        raise AnchorSignatureError(f"{label} must be base64 text")

    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure
        raise AnchorSignatureError(
            f"{label} is not valid base64"
        ) from exc


def anchor_digest(value: Any) -> str:
    """The canonical digest of one anchor's value.

    A reader returns whatever is meaningful for its anchor; the digest is
    always computed here, over the same encoding, so two anchors of the same
    kind are comparable without this module knowing their internals.
    """

    return hashlib.sha256(
        _canonical_bytes({"domain": ANCHOR_DOMAIN, "value": value})
    ).hexdigest()


# =====================================================================
# Errors
# =====================================================================


class AnchorError(Exception):
    """Base error for the external anchoring layer.

    Every subclass names one way an anchor can fail to be provable, so the
    enforcement path turns it into a refusal reason without inventing one --
    and so an operator reading the audit trail sees which property broke
    rather than that "something went wrong".
    """

    #: The refusal-reason fragment this error maps to on the boundary.
    reason = "anchor_error"


class AnchorUnknownError(AnchorError):
    """No anchor exists for the id asked about, or no reader was bound."""

    reason = "anchor_missing"


class AnchorMismatchError(AnchorError):
    """The local anchor and the confirmed checkpoint disagree at one position."""

    reason = "anchor_mismatch"


class AnchorRewindError(AnchorError):
    """A checkpoint was presented at or below the sequence already published."""

    reason = "anchor_rewind"


class AnchorTruncatedError(AnchorError):
    """The confirmed checkpoint names a sequence the anchor no longer has."""

    reason = "anchor_truncated"


class AnchorUnconfirmedError(AnchorError):
    """No checkpoint has been confirmed for this anchor and the gate is on."""

    reason = "anchor_unconfirmed"


class AnchorWitnessUnavailableError(AnchorError):
    """The witness refused, was absent, or could not be reached."""

    reason = "anchor_witness_unavailable"


class AnchorSignatureError(AnchorError):
    """A checkpoint's signature does not verify, or its id does not re-derive."""

    reason = "anchor_signature_invalid"


class AnchorJournalError(AnchorError):
    """The journal could not read or persist what it was asked to."""

    reason = "anchor_store_error"


# =====================================================================
# Findings
# =====================================================================


@dataclass(frozen=True)
class AnchorFinding:
    """One refused anchor operation, kept as evidence of the attempt.

    A finding is not a violation: it is the mechanism working. It is kept so
    an operator can see that something tried to rewind an anchor or present
    a checkpoint the witness never signed, and so the invariant can tell "an
    attack was attempted and refused" from "the anchor says something
    untrue".
    """

    kind: str
    anchor_kind: str
    anchor_id: str
    sequence: int
    detail: str
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "anchor_kind": self.anchor_kind,
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "detail": self.detail,
            "at": self.at,
        }


#: The finding kinds this release produces. Anything else is a finding the
#: invariant cannot explain, which it reports rather than ignoring.
ANCHOR_FINDING_KINDS: frozenset[str] = frozenset(
    {
        #: The local anchor and the confirmed checkpoint disagree.
        "mismatch",
        #: A checkpoint presented at or below the published sequence.
        "rewind",
        #: The anchor lost positions the witness already confirmed.
        "truncated",
        #: No checkpoint confirmed for this anchor.
        "unconfirmed",
        #: The witness refused, was absent, or was unreachable.
        "witness_unavailable",
        #: A signature that does not verify, or an id that does not re-derive.
        "signature_invalid",
        #: A backend the journal could not read or write.
        "unverifiable",
    }
)


# =====================================================================
# Checkpoints
# =====================================================================


@dataclass(frozen=True)
class AnchorCheckpoint:
    """A signed statement about one anchor at one instant.

    ``checkpoint_id`` is the digest of everything below the signature, so a
    checkpoint whose stored id does not re-derive from its own fields is a
    forged or edited one -- which is exactly what the invariant reports.
    ``issued_at`` is the *witness's* statement about time and carries no
    guarantee: it is the monotone ``sequence`` that orders checkpoints, not
    the clock.
    """

    kind: AnchorKind
    anchor_id: str
    sequence: int
    digest: str
    issued_at: float
    witness_key_id: str = ""
    algorithm: str = "Ed25519"
    signature: str = ""
    checkpoint_id: str = ""

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def signed_payload(self) -> bytes:
        """Everything the signature covers, and nothing else.

        The signature is deliberately *outside* the block: a signature
        cannot cover itself, and a checkpoint whose id included its own
        signature could never re-derive.
        """

        return _canonical_bytes(
            {
                "domain": ANCHOR_DOMAIN,
                "kind": self.kind.value,
                "anchor_id": self.anchor_id,
                "sequence": int(self.sequence),
                "digest": self.digest,
                "issued_at": self.issued_at,
                "witness_key_id": self.witness_key_id,
                "algorithm": self.algorithm,
            }
        )

    def rederived_id(self) -> str:
        """The id this checkpoint's own fields describe."""

        return hashlib.sha256(self.signed_payload()).hexdigest()

    def is_signed(self) -> bool:
        return bool(self.signature) and bool(self.witness_key_id)

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "kind": self.kind.value,
            "anchor_id": self.anchor_id,
            "sequence": int(self.sequence),
            "digest": self.digest,
            "issued_at": self.issued_at,
            "witness_key_id": self.witness_key_id,
            "algorithm": self.algorithm,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "AnchorCheckpoint":
        """Rebuild a checkpoint from stored or received bytes.

        Every field is validated rather than coerced. A parser that
        tolerated a wrong type would be inventing a checkpoint to verify,
        and the one thing this layer must never do is verify something
        nobody signed.
        """

        if not isinstance(payload, dict):
            raise AnchorSignatureError(
                "a checkpoint must be an object"
            )

        kind = anchor_kind_of(payload.get("kind"))

        if kind is None:
            raise AnchorSignatureError(
                f"unknown anchor kind: {payload.get('kind')!r}"
            )

        anchor_id = payload.get("anchor_id")

        if not isinstance(anchor_id, str) or not anchor_id.strip():
            raise AnchorSignatureError(
                "anchor_id must be a non-empty string"
            )

        sequence = payload.get("sequence")

        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise AnchorSignatureError("sequence must be an integer")

        # Zero is a legitimate position, not a malformed one: a lineage's
        # genesis link sits at sequence 0, so an anchor published over a
        # fresh chain -- the first thing a deployment that turns the gate on
        # does -- is a checkpoint at 0. Refusing it here would make such a
        # checkpoint storable but unreadable, so a durable anchor store would
        # fail to load at construction and the process would refuse to start
        # after a perfectly ordinary first run. Only a negative position is
        # meaningless, and that is what this refuses.
        if sequence < 0:
            raise AnchorSignatureError("sequence must not be negative")

        digest = payload.get("digest")

        if not isinstance(digest, str) or not digest.strip():
            raise AnchorSignatureError(
                "digest must be a non-empty string"
            )

        issued_at = payload.get("issued_at")

        if isinstance(issued_at, bool) or not isinstance(
            issued_at, (int, float)
        ):
            raise AnchorSignatureError("issued_at must be a number")

        algorithm = payload.get("algorithm", "Ed25519")

        if algorithm not in SUPPORTED_ALGORITHMS:
            raise AnchorSignatureError(
                f"unsupported algorithm: {algorithm!r}"
            )

        witness_key_id = payload.get("witness_key_id", "")
        signature = payload.get("signature", "")
        checkpoint_id = payload.get("checkpoint_id", "")

        for label, value in (
            ("witness_key_id", witness_key_id),
            ("signature", signature),
            ("checkpoint_id", checkpoint_id),
        ):
            if not isinstance(value, str):
                raise AnchorSignatureError(f"{label} must be a string")

        return cls(
            kind=kind,
            anchor_id=anchor_id,
            sequence=int(sequence),
            digest=digest,
            issued_at=float(issued_at),
            witness_key_id=witness_key_id,
            algorithm=algorithm,
            signature=signature,
            checkpoint_id=checkpoint_id,
        )


# =====================================================================
# Witnesses
# =====================================================================


class AnchorWitness:
    """The interface a witness must satisfy.

    The protocol does not care what a witness *is* -- a remote service, a
    transparency log, a peer process, a write-once medium, an HSM, a
    different machine under a different account. What matters is one
    property: the witness is not writable by the process that runs the
    firewall. That property is a fact about the operator's infrastructure
    and this package cannot check it, so it ships the interface rather than
    a claim.
    """

    #: A stable label, so a refusal can name which witness refused.
    name = "witness"

    def sign(self, checkpoint: AnchorCheckpoint) -> AnchorCheckpoint:
        raise NotImplementedError


class NullWitness(AnchorWitness):
    """A witness that refuses everything.

    This is what an SDK holds when no witness was configured, and it refuses
    rather than signing, which is what makes the gate impossible to satisfy
    by accident: a deployment that never configured a witness gets
    ``anchor_witness_unavailable``, not a green check.
    """

    name = "null"

    def sign(self, checkpoint: AnchorCheckpoint) -> AnchorCheckpoint:
        raise AnchorWitnessUnavailableError(
            "no witness is configured, so nothing can be anchored"
        )


class InProcessWitness(AnchorWitness):
    """A witness held by the process it is supposed to be independent of.

    **This is not a witness.** It provides no independence whatsoever: the
    same process that runs the firewall holds the signing key, so an
    attacker who can rewrite the local store can rewrite the checkpoints
    just as easily. Using it in a deployment is a silent downgrade to v3.3
    with extra steps, and the layer's whole point is lost.

    It exists for two callers and no others: the invariant estate, which
    needs *something* that signs so ``EXTERNAL_ANCHOR_SOUNDNESS`` has state
    to inspect, and the test suite, which needs to mint genuine and
    deliberately broken checkpoints to attack the layer with. Both of those
    run in one process by construction. A deployment that wants the
    property wants :class:`LocalFileWitness` on separate storage or a
    :class:`RemoteWitness` behind a transport the firewall cannot write.
    """

    name = "in-process"

    def __init__(
        self,
        *,
        key_id: str,
        private_key: Ed25519PrivateKey,
    ):
        if not isinstance(key_id, str) or not key_id.strip():
            raise AnchorSignatureError(
                "key_id must be a non-empty string"
            )

        if not isinstance(private_key, Ed25519PrivateKey):
            raise AnchorSignatureError(
                "private_key must be an Ed25519PrivateKey"
            )

        self.key_id = key_id
        self._private_key = private_key

    def sign(self, checkpoint: AnchorCheckpoint) -> AnchorCheckpoint:
        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        stamped = replace(
            checkpoint,
            witness_key_id=self.key_id,
            signature="",
            checkpoint_id="",
        )

        return replace(
            stamped,
            signature=_b64encode(
                self._private_key.sign(stamped.signed_payload())
            ),
            checkpoint_id=stamped.rederived_id(),
        )


class LocalFileWitness(AnchorWitness):
    """A witness that appends checkpoints to a local file and signs them.

    A **test and single-host affordance**, and it says so rather than
    implying more. It demonstrates the protocol and it is enough to make the
    layer exercisable, but a file on the same host is not independent
    storage: a deployment that needs the property needs a witness the
    firewall's process cannot write, and this one does not qualify.
    """

    name = "local-file"

    def __init__(
        self,
        path: str | Path,
        *,
        key_id: str,
        private_key: Ed25519PrivateKey,
    ):
        if not isinstance(key_id, str) or not key_id.strip():
            raise AnchorSignatureError(
                "key_id must be a non-empty string"
            )

        if not isinstance(private_key, Ed25519PrivateKey):
            raise AnchorSignatureError(
                "private_key must be an Ed25519PrivateKey"
            )

        self.path = Path(path)
        self.key_id = key_id
        self._private_key = private_key
        self._lock = RLock()

    def sign(self, checkpoint: AnchorCheckpoint) -> AnchorCheckpoint:
        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        # The witness key id is inside the signed block, so it has to be
        # stamped before the payload is built -- which is the point: a
        # checkpoint cannot be re-attributed to another witness after the
        # fact, because moving the attribution moves the signature.
        stamped = replace(
            checkpoint,
            witness_key_id=self.key_id,
            signature="",
            checkpoint_id="",
        )

        signed = replace(
            stamped,
            signature=_b64encode(
                self._private_key.sign(stamped.signed_payload())
            ),
            checkpoint_id=stamped.rederived_id(),
        )

        try:
            with self._lock:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            signed.to_dict(),
                            sort_keys=True,
                        )
                        + "\n"
                    )
        except OSError as exc:
            raise AnchorWitnessUnavailableError(
                f"the witness could not record the checkpoint: "
                f"{type(exc).__name__}"
            ) from exc

        return signed


class RemoteWitness(AnchorWitness):
    """A witness reached through an operator-supplied transport.

    The transport is a single callable that takes a checkpoint's wire form
    and returns the witness's signed reply. Everything protocol-shaped lives
    here; everything transport-shaped is the deployment's, because this
    package has no business guessing whether an operator speaks HTTP, gRPC,
    a message queue or a signed email.
    """

    name = "remote"

    def __init__(self, transport: Callable[[dict[str, Any]], Any]):
        if not callable(transport):
            raise TypeError("transport must be callable")

        self._transport = transport

    def sign(self, checkpoint: AnchorCheckpoint) -> AnchorCheckpoint:
        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        try:
            reply = self._transport(checkpoint.to_dict())
        except AnchorError:
            raise
        except Exception as exc:  # noqa: BLE001 - any transport failure
            raise AnchorWitnessUnavailableError(
                f"the witness could not be reached: {type(exc).__name__}"
            ) from exc

        try:
            return AnchorCheckpoint.from_dict(reply)
        except AnchorError:
            raise
        except Exception as exc:  # noqa: BLE001 - a malformed reply
            raise AnchorSignatureError(
                "the witness replied with something that is not a "
                f"checkpoint: {type(exc).__name__}"
            ) from exc


def verify_checkpoint_signature(
    checkpoint: AnchorCheckpoint,
    public_key: Ed25519PublicKey,
) -> bool:
    """Whether ``checkpoint`` carries a valid signature under ``public_key``.

    Returns a boolean rather than raising, because every caller here is
    deciding a verdict and a verdict belongs in a return value. A malformed
    signature is ``False``, not an exception: "I could not verify this" and
    "this does not verify" are the same answer on a progression path.
    """

    if not checkpoint.is_signed():
        return False

    try:
        signature = _b64decode(checkpoint.signature, "signature")
    except AnchorError:
        return False

    try:
        public_key.verify(signature, checkpoint.signed_payload())
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - any verification failure
        return False

    return True


# =====================================================================
# The journal
# =====================================================================


class AnchorJournal:
    """The anchor journal: publish, confirm, compare.

    Three operations, and none of them can widen authority. ``publish``
    takes an anchor's current value and has the witness sign it. ``confirm``
    records the witness's signed reply locally, refusing anything that does
    not verify against a registered witness key, does not re-derive to its
    own id, or is not ahead of the last confirmed sequence. ``compare`` is
    what a progression path calls, and it returns a refusal reason or
    ``None`` -- never a permission.

    Two readers per kind, and the second is what makes ``compare`` sound
    rather than merely plausible: one says where an anchor is now, the other
    says what it committed to at a position it has since moved past. An
    anchor that moved on by rewriting its own prefix is invisible to a
    head-only comparison, which is precisely the rewrite this layer exists
    to refuse.
    """

    #: The methods that drive the journal. The release's source census
    #: closes over exactly these names in both directions.
    MUTATOR_CALLS: tuple[str, ...] = ("publish", "confirm", "record_finding")

    def __init__(
        self,
        *,
        clock: Any = None,
        backend: Any = None,
        witness: Optional[AnchorWitness] = None,
        witness_keys: Optional[
            Mapping[str, Ed25519PublicKey]
        ] = None,
    ):
        self._clock = clock if clock is not None else time.time
        self._backend = backend
        self._witness = (
            witness if witness is not None else NullWitness()
        )
        self._witness_keys: dict[str, Ed25519PublicKey] = {}

        if witness_keys:
            for key_id, public_key in witness_keys.items():
                self.register_witness_key(key_id, public_key)

        self._readers: dict[AnchorKind, AnchorReader] = {}
        self._prefix_readers: dict[AnchorKind, AnchorPrefixReader] = {}
        self._findings: list[AnchorFinding] = []
        self._published: list[AnchorCheckpoint] = []
        self._confirmed: list[AnchorCheckpoint] = []
        self._lock = RLock()

        # The journal holds its own account of what it published and
        # confirmed; the backend is durability, not the source of truth. An
        # in-memory deployment -- the invariant estate, a test, a
        # single-shot process -- is therefore fully checkable, which is what
        # lets EXTERNAL_ANCHOR_SOUNDNESS report on one at all. A backend
        # that could not be read is a denial rather than an empty journal:
        # "I could not read the confirmed set" and "there is no confirmed
        # set" are different statements, and only one of them is safe.
        if self._backend is not None:
            try:
                self._published = list(self._backend.load())
                self._confirmed = list(
                    self._backend.load(confirmed_only=True)
                )
            except Exception as exc:  # noqa: BLE001 - unreadable state
                raise AnchorJournalError(
                    "the anchor store could not be read at construction"
                ) from exc

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
        key_id: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        """Register the public half of a witness key.

        Registration is the whole of this firewall's authority over a
        witness: it cannot tell whether the key really belongs to the system
        the id names, and it does not pretend to. What it can do is refuse
        anything signed by a key nobody registered.
        """

        if not isinstance(key_id, str) or not key_id.strip():
            raise AnchorSignatureError(
                "key_id must be a non-empty string"
            )

        if not isinstance(public_key, Ed25519PublicKey):
            raise AnchorSignatureError(
                "public_key must be an Ed25519PublicKey"
            )

        self._witness_keys[key_id] = public_key

    def witness_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._witness_keys))

    def verify_receipt(self, checkpoint: Any) -> bool:
        """Whether a checkpoint re-derives and verifies under a registered key.

        The predicate the invariant asks of every stored row: a receipt that
        does not re-derive to its own id, or whose signature does not verify
        under a key this journal has registered, is evidence of nothing.
        Returns a boolean rather than raising, because it is answering a
        question about a record rather than deciding a progression.
        """

        if not isinstance(checkpoint, AnchorCheckpoint):
            return False

        if checkpoint.rederived_id() != checkpoint.checkpoint_id:
            return False

        public_key = self._witness_keys.get(checkpoint.witness_key_id)

        if public_key is None:
            return False

        return verify_checkpoint_signature(checkpoint, public_key)

    def bind_reader(self, kind: AnchorKind, reader: AnchorReader) -> None:
        """Bind the reader that supplies one anchor's current value.

        The journal never reaches into another layer's storage itself: it
        asks the owner, through a callable the owner supplied. A kind with
        no bound reader is ``anchor_missing`` rather than "assume it is
        fine", which is the same rule every other unprovable state gets.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None:
            raise AnchorUnknownError(f"unknown anchor kind: {kind!r}")

        if not callable(reader):
            raise TypeError("reader must be callable")

        self._readers[resolved] = reader

    def bind_prefix_reader(
        self,
        kind: AnchorKind,
        reader: AnchorPrefixReader,
    ) -> None:
        """Bind the reader that supplies one anchor's committed value *at* a
        sequence.

        ``compare`` needs this to answer the question the head reader cannot:
        when the live anchor has moved past the last confirmed checkpoint, is
        the confirmed commitment still part of the chain the anchor now
        presents? Checking only the head would leave that case unexamined, and
        the case is not hypothetical -- an attacker who rewrites a store to a
        fabricated but internally consistent history *longer* than the
        confirmed one presents a head at a higher sequence, which no
        head-only comparison ever contradicts.

        A kind with no bound prefix reader is ``anchor_missing`` in that case,
        never "assume the prefix survived" -- the same rule
        :meth:`bind_reader` states for an anchor nobody can read.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None:
            raise AnchorUnknownError(f"unknown anchor kind: {kind!r}")

        if not callable(reader):
            raise TypeError("reader must be callable")

        self._prefix_readers[resolved] = reader

    def bound_kinds(self) -> tuple[str, ...]:
        return tuple(sorted(kind.value for kind in self._readers))

    def prefix_bound_kinds(self) -> tuple[str, ...]:
        """The kinds whose confirmed prefix this journal can verify."""

        return tuple(sorted(kind.value for kind in self._prefix_readers))

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _record(
        self,
        kind: str,
        anchor_kind: Any,
        anchor_id: str,
        sequence: int,
        detail: str,
    ) -> AnchorFinding:
        finding = AnchorFinding(
            kind=kind,
            anchor_kind=(
                anchor_kind.value
                if isinstance(anchor_kind, AnchorKind)
                else str(anchor_kind)
            ),
            anchor_id=str(anchor_id),
            sequence=int(sequence),
            detail=str(detail),
            at=self._now(),
        )

        with self._lock:
            self._findings.append(finding)

        return finding

    def record_finding(
        self,
        kind: str,
        *,
        anchor_kind: Any = "",
        anchor_id: str = "",
        sequence: int = 0,
        detail: str = "",
    ) -> AnchorFinding:
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
            detail,
        )

    def findings(self) -> tuple[AnchorFinding, ...]:
        with self._lock:
            return tuple(self._findings)

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(
        self,
        kind: AnchorKind,
        anchor_id: str,
    ) -> AnchorCheckpoint:
        """Take the anchor's current value and have the witness sign it.

        Refuses ``anchor_rewind`` when the new checkpoint would sit at or
        below the sequence already published for this anchor -- that is the
        "restore an older snapshot" attack, refused before the witness ever
        sees it.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None:
            raise AnchorUnknownError(f"unknown anchor kind: {kind!r}")

        if not isinstance(anchor_id, str) or not anchor_id.strip():
            raise AnchorUnknownError("anchor_id must be a non-empty string")

        reader = self._readers.get(resolved)

        if reader is None:
            self._record(
                "unverifiable",
                resolved,
                anchor_id,
                0,
                "no reader is bound for this anchor kind",
            )
            raise AnchorUnknownError(
                f"no reader is bound for {resolved.value}"
            )

        try:
            current = reader(anchor_id)
        except Exception as exc:  # noqa: BLE001 - an unreadable anchor
            self._record(
                "unverifiable",
                resolved,
                anchor_id,
                0,
                f"the anchor could not be read: {type(exc).__name__}",
            )
            raise AnchorJournalError(
                f"the {resolved.value} anchor could not be read"
            ) from exc

        if current is None:
            self._record(
                "unverifiable",
                resolved,
                anchor_id,
                0,
                "the anchor does not exist",
            )
            raise AnchorUnknownError(
                f"no {resolved.value} anchor exists for this id"
            )

        sequence, digest = current

        previous = self.for_anchor(resolved, anchor_id)

        if previous is not None and int(sequence) <= int(previous.sequence):
            self._record(
                "rewind",
                resolved,
                anchor_id,
                int(sequence),
                f"published sequence {previous.sequence} is at or ahead of "
                f"the presented {sequence}",
            )
            raise AnchorRewindError(
                f"the {resolved.value} anchor is at sequence {sequence} but "
                f"sequence {previous.sequence} was already published"
            )

        draft = AnchorCheckpoint(
            kind=resolved,
            anchor_id=anchor_id,
            sequence=int(sequence),
            digest=str(digest),
            issued_at=self._now(),
        )

        try:
            signed = self._witness.sign(draft)
        except AnchorError as exc:
            self._record(
                "witness_unavailable",
                resolved,
                anchor_id,
                int(sequence),
                f"{type(exc).__name__}: {exc}",
            )
            raise
        except Exception as exc:  # noqa: BLE001 - any witness failure
            self._record(
                "witness_unavailable",
                resolved,
                anchor_id,
                int(sequence),
                f"the witness failed: {type(exc).__name__}",
            )
            raise AnchorWitnessUnavailableError(
                f"the witness failed: {type(exc).__name__}"
            ) from exc

        if not isinstance(signed, AnchorCheckpoint):
            raise AnchorSignatureError(
                "the witness returned something that is not a checkpoint"
            )

        if signed.rederived_id() != signed.checkpoint_id:
            self._record(
                "signature_invalid",
                resolved,
                anchor_id,
                int(sequence),
                "the witness returned a checkpoint whose id does not "
                "re-derive",
            )
            raise AnchorSignatureError(
                "the witness returned a checkpoint whose id does not "
                "re-derive from its own fields"
            )

        if signed.kind is not resolved or signed.anchor_id != anchor_id:
            raise AnchorSignatureError(
                "the witness returned a checkpoint about another anchor"
            )

        if int(signed.sequence) != int(sequence) or signed.digest != str(
            digest
        ):
            self._record(
                "mismatch",
                resolved,
                anchor_id,
                int(sequence),
                "the witness returned a checkpoint about another value",
            )
            raise AnchorMismatchError(
                "the witness returned a checkpoint about a different value "
                "than the one it was given"
            )

        if self._backend is not None:
            try:
                self._backend.insert(signed, confirmed=False)
            except AnchorError:
                raise
            except Exception as exc:  # noqa: BLE001 - a backend failure
                raise AnchorJournalError(
                    "the anchor store refused the checkpoint"
                ) from exc

        with self._lock:
            self._published.append(signed)

        return signed

    # ------------------------------------------------------------------
    # Confirm
    # ------------------------------------------------------------------

    def confirm(self, checkpoint: Any) -> AnchorCheckpoint:
        """Record the witness's signed reply, refusing anything unverifiable.

        Four refusals, in the order that makes each one meaningful: the
        checkpoint must re-derive to its own id, must carry a signature from
        a *registered* witness key, must verify under that key, and must not
        be at or below the sequence already confirmed. Nothing that fails is
        stored.
        """

        if isinstance(checkpoint, dict):
            checkpoint = AnchorCheckpoint.from_dict(checkpoint)

        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        if checkpoint.rederived_id() != checkpoint.checkpoint_id:
            self._record(
                "signature_invalid",
                checkpoint.kind,
                checkpoint.anchor_id,
                checkpoint.sequence,
                "the checkpoint id does not re-derive from its own fields",
            )
            raise AnchorSignatureError(
                "the checkpoint id does not re-derive from its own fields"
            )

        public_key = self._witness_keys.get(checkpoint.witness_key_id)

        if public_key is None:
            self._record(
                "signature_invalid",
                checkpoint.kind,
                checkpoint.anchor_id,
                checkpoint.sequence,
                f"witness key {checkpoint.witness_key_id!r} is not registered",
            )
            raise AnchorSignatureError(
                "the checkpoint is signed by a key that is not registered"
            )

        if not verify_checkpoint_signature(checkpoint, public_key):
            self._record(
                "signature_invalid",
                checkpoint.kind,
                checkpoint.anchor_id,
                checkpoint.sequence,
                "the signature does not verify under the registered key",
            )
            raise AnchorSignatureError(
                "the checkpoint's signature does not verify"
            )

        last = self.last_confirmed(checkpoint.kind, checkpoint.anchor_id)

        if last is not None and int(checkpoint.sequence) <= int(last.sequence):
            self._record(
                "rewind",
                checkpoint.kind,
                checkpoint.anchor_id,
                checkpoint.sequence,
                f"a checkpoint at sequence {last.sequence} is already "
                "confirmed",
            )
            raise AnchorRewindError(
                f"a checkpoint at sequence {last.sequence} is already "
                "confirmed for this anchor"
            )

        if self._backend is not None:
            try:
                self._backend.insert(checkpoint, confirmed=True)
            except AnchorError:
                raise
            except Exception as exc:  # noqa: BLE001 - a backend failure
                raise AnchorJournalError(
                    "the anchor store refused the receipt"
                ) from exc

        with self._lock:
            self._confirmed.append(checkpoint)

        return checkpoint

    # ------------------------------------------------------------------
    # Compare -- the progression gate
    # ------------------------------------------------------------------

    def compare(
        self,
        kind: AnchorKind,
        anchor_id: str,
    ) -> Optional[str]:
        """The refusal reason for this anchor, or ``None`` when it agrees.

        One-directional by construction: this returns a *reason to refuse*
        or nothing at all. There is no return value that says "allowed",
        because a layer that could say that would be a second authorization
        path.

        Four questions, in the order that makes each one meaningful: is there
        a confirmed checkpoint at all; can the anchor be read; is the anchor
        *behind* the confirmed position (truncation); and does the anchor
        still carry the commitment the confirmed checkpoint names. The last
        one is asked at the confirmed sequence rather than at the head,
        because the head may legitimately have moved on -- and an anchor that
        moved on by rewriting its prefix is exactly the attack a head-only
        comparison would miss.
        """

        resolved = anchor_kind_of(kind)

        if resolved is None:
            return "anchor_missing"

        if not isinstance(anchor_id, str) or not anchor_id.strip():
            return "anchor_missing"

        last = self.last_confirmed(resolved, anchor_id)

        if last is None:
            return "anchor_unconfirmed"

        reader = self._readers.get(resolved)

        if reader is None:
            return "anchor_missing"

        try:
            current = reader(anchor_id)
        except Exception:  # noqa: BLE001 - an unreadable anchor
            return "anchor_missing"

        if current is None:
            return "anchor_missing"

        sequence, digest = current

        if int(sequence) < int(last.sequence):
            return "anchor_truncated"

        if int(sequence) == int(last.sequence):
            if str(digest) != last.digest:
                return "anchor_mismatch"

            return None

        # The anchor has moved past the confirmed checkpoint, so the head
        # says nothing about it. Ask the anchor what it committed to *at* the
        # confirmed sequence instead: a chain that was rewritten into a
        # longer, internally consistent history no longer carries the
        # confirmed commitment there, and that is the whole of the defence.
        prefix_reader = self._prefix_readers.get(resolved)

        if prefix_reader is None:
            return "anchor_missing"

        try:
            committed = prefix_reader(anchor_id, int(last.sequence))
        except Exception:  # noqa: BLE001 - an unreadable anchor
            return "anchor_missing"

        if committed is None:
            return "anchor_truncated"

        if str(committed) != last.digest:
            return "anchor_mismatch"

        return None

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    @staticmethod
    def _latest(
        rows: tuple[AnchorCheckpoint, ...],
        resolved: AnchorKind,
        anchor_id: str,
    ) -> Optional[AnchorCheckpoint]:
        """The highest-sequence checkpoint for one anchor within one set."""

        best: Optional[AnchorCheckpoint] = None

        for checkpoint in rows:
            if checkpoint.kind is not resolved:
                continue

            if checkpoint.anchor_id != anchor_id:
                continue

            if best is None or checkpoint.sequence > best.sequence:
                best = checkpoint

        return best

    def for_anchor(
        self,
        kind: AnchorKind,
        anchor_id: str,
    ) -> Optional[AnchorCheckpoint]:
        """The latest *published* checkpoint for one anchor, or ``None``."""

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return None

        with self._lock:
            rows = tuple(self._published)

        return self._latest(rows, resolved, anchor_id)

    def last_confirmed(
        self,
        kind: AnchorKind,
        anchor_id: str,
    ) -> Optional[AnchorCheckpoint]:
        """The latest *confirmed* checkpoint for one anchor, or ``None``."""

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return None

        with self._lock:
            rows = tuple(self._confirmed)

        return self._latest(rows, resolved, anchor_id)

    def records(self) -> tuple[AnchorCheckpoint, ...]:
        """Every published checkpoint, oldest first."""

        with self._lock:
            return tuple(self._published)

    def receipts(self) -> tuple[AnchorCheckpoint, ...]:
        """Every confirmed checkpoint, oldest first."""

        with self._lock:
            return tuple(self._confirmed)

    def size(self) -> int:
        return len(self.records())


__all__ = [
    "ANCHOR_DOMAIN",
    "ANCHOR_FINDING_KINDS",
    "SUPPORTED_ALGORITHMS",
    "AnchorCheckpoint",
    "AnchorError",
    "AnchorFinding",
    "AnchorJournal",
    "AnchorJournalError",
    "AnchorKind",
    "AnchorMismatchError",
    "AnchorReader",
    "AnchorRewindError",
    "AnchorSignatureError",
    "AnchorTruncatedError",
    "AnchorUnconfirmedError",
    "AnchorUnknownError",
    "AnchorWitness",
    "AnchorWitnessUnavailableError",
    "InProcessWitness",
    "LocalFileWitness",
    "NullWitness",
    "RemoteWitness",
    "anchor_digest",
    "anchor_kind_of",
    "verify_checkpoint_signature",
]
