"""Canonical, integrity-bound commitments of the authorization security state.

Why this exists
---------------

:meth:`firewall.sdk.FirewallSDK.authorize` decides from security state
held in several stores: the revocation registry, the issuer trust store,
the delegation lineage, and the delegation-depth ceiling. v2.6 made the
*epoch* count the writes to that state that can widen authority, so a
verdict is refused when a widening write lands between two of its reads.
But the epoch counts *writes*, not *state*. A store mutated without its
declared write path -- a revocation record removed by hand, an edge in
the lineage overwritten, a store file rolled back to an earlier snapshot,
a cross-store update that crashed half-way -- moves the state without
moving the counter. The v2.6 proof is about the counter; v3.0 extends it
to the state the counter stands in for.

The claim made here is the v3.0 core property:

    An authorization decision must never rely on a security state the
    firewall cannot prove is coherent.

A state is *coherent* when the firewall can prove it is exactly the state
the firewall itself last recorded. Two things make that proof possible,
and this module provides both:

1. **A canonical digest** of the security state the ALLOW boundary reads.
   The digest is computed from each in-domain store through a declared
   reader, under one journal lock, so a snapshot cannot be assembled from
   two different instants (no TOCTOU between stores).

2. **An append-only, hash-chained commitment journal.** Every legitimate
   in-domain store write is bracketed by ``record_state_commit`` (the
   write-side sibling of the epoch's ``record_widening``), and on exit of
   the bracket the journal appends a record chaining the new digest to
   the previous one. The head of that chain is the firewall's own
   statement of what its security state is.

   The ALLOW path therefore demands, immediately before an allow is
   emitted, that the *live* digest equals the chain head. Any change that
   did not go through a declared write path -- tampering, rollback, a
   torn transition, a crash between a store write and its commitment --
   leaves the live state disagreeing with the last thing the firewall
   recorded, and the request is refused as ``state_incoherent``. The
   epoch still owns mid-request *widening* detection; this owns "the
   state being read is the state the firewall can account for".

Failure is one-directional, and deliberately so, exactly like the epoch:
a journal that cannot prove the state coherent can only turn an allow
into a denial. No value in the journal, and no digest computation, ever
permits anything -- ``FirewallSDK.authorize()`` remains the only path
that can, and this module constructs no ``AuthorizationResult``.

What is in the domain, and what is not
--------------------------------------

The digest domain is the security state whose silent mutation could turn
a future denial into an allow and that is not re-derived from the
firewall's own verdicts:

* the **revocation registry** (records),
* the **issuer trust store** (trusted issuers),
* the **delegation lineage** (registered edges),
* the **delegation-depth ceiling** the boundary enforces.

Deliberately absent, each for a stated reason:

* **Refusal state, runtime/semantic/risk contexts.** These are written
  by the authorization path itself -- a denial records a refusal memo, an
  allow consumes budget -- so freezing their content into a digest the
  boundary must re-verify would make every verdict self-inconsistent.
  Their *widening* mutations are whole-store replacements or clears that
  are epoch-bracketed at the store, which is the guarantee they need.
* **Aegis restrictions.** Removing a restriction is a widening, and
  restriction writes are epoch-bracketed at the store; moreover a grant
  cannot regain ``ACTIVE`` standing without a canonical ``authorize()``
  allow, so a restriction-store edit alone cannot restore authority.
* **Evidence/execution/effect/verification journals.** They are written
  only by the boundary's own record paths and are never read by the ALLOW
  gates; each has its own chained/derived-id integrity (v1.8, v2.7-v2.9).

The census in :data:`STATE_COMMIT_WRITES` is where "these are the only
write paths" is recorded. The ``SECURITY_STATE_COHERENCE`` invariant
checks it in both directions: a write named there that does not open a
commitment bracket is a violation, and a bracket opened anywhere else is
one too, so a later change cannot quietly add an in-domain write and
pass by bracketing it.

A note on what cannot be claimed. A complete, consistent rollback of
every store *and* the commitment journal to an earlier valid snapshot is
indistinguishable from that earlier snapshot being the present -- the
same time-machine boundary the epoch has, and the same reason a v3.0
deployment anchors the journal on durable storage. What the mechanism
catches is any divergence between the recorded state and the actual
state, which is the class of attack a single store file can produce.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Mapping, Optional

__all__ = [
    "STATE_COMMIT_ANCHOR",
    "STATE_COMMIT_HELPER",
    "STATE_COMMIT_WRITES",
    "StateCommitError",
    "StateCommitJournal",
    "StateCommitRecord",
    "bind_state_commit",
    "state_commit_of",
    "record_state_commit",
]

#: Fixed domain prefix so digests from unrelated deployments or versions
#: can never accidentally agree. Every component digest and every chain
#: digest is a hash over a payload that begins with this literal.
DOMAIN = "agent-firewall/state-commit/v1"

#: The digest a genesis record chains from. A constant anchor rather than
#: a zero string, so a forged record cannot claim "no predecessor" by
#: pointing at an all-zero parent; forging it still requires recomputing
#: the anchor literal, which is the same bar as forging a digest.
STATE_COMMIT_ANCHOR = hashlib.sha256(
    (DOMAIN + "/genesis").encode("utf-8")
).hexdigest()

#: The helper name the census recognises at a call site, mirrored from
#: :data:`firewall.authority_epoch.EPOCH_BRACKET_HELPERS`. Deliberately
#: loose for the same reason that census is: a false positive makes the
#: census *require* an entry, which a reviewer resolves by looking; a
#: false negative would let a real in-domain write go uncommitted and
#: report a pass.
STATE_COMMIT_HELPER = "record_state_commit"

#: Every write in the package that mutates the canonical security state,
#: and therefore must open a state-commitment interval.
#:
#: This is a census, not a description: the SECURITY_STATE_COHERENCE
#: invariant checks it in **both** directions. A function listed here
#: without a ``record_state_commit`` bracket is a violation, and a
#: bracket in a function not listed here is also a violation. The second
#: direction is the one that matters over time: a later change cannot
#: quietly add an in-domain write and satisfy the invariant by bracketing
#: it, because the census literal is where the sentence "these are all of
#: them" is recorded.
STATE_COMMIT_WRITES = frozenset(
    {
        ("firewall/key_management.py", "IssuerTrustStore.trust"),
        ("firewall/key_management.py", "IssuerTrustStore.revoke"),
        ("firewall/revocation.py", "RevocationRegistry.revoke"),
        ("firewall/delegation_lineage.py", "DelegationLineage.register"),
        ("firewall/delegation_lineage.py", "DelegationLineage.clear"),
        ("firewall/sdk.py", "FirewallSDK.max_delegation_depth"),
    }
)

#: The denial-reason prefix the ALLOW path uses when state cannot be
#: proved coherent. Declared so callers partitioning verdicts by cause
#: can ask ``reason.startswith(STATE_INCOHERENT_PREFIX)`` instead of
#: embedding the literal -- and so the adversarial test suite can assert
#: on it without duplicating a string that must not drift.
STATE_INCOHERENT_PREFIX = "state_incoherent"

#: Names that may not appear in a reader/component label, because the
#: composite digest joins labels and digests with these characters.
_RESERVED_LABEL_CHARS = frozenset("=;\x00\x1f\n")


class StateCommitError(Exception):
    """Raised when the commitment journal cannot do its job.

    A journal that cannot read a component, cannot persist a record, or
    loads a chain that fails to verify has failed at the one thing it
    exists to do -- proving the state coherent. Callers treat this as a
    denial (``security_state_unavailable``), never as a pass.
    """


@dataclass(frozen=True)
class StateCommitRecord:
    """One link in the state-commitment hash chain.

    ``state_digest`` is the canonical digest of the whole in-domain
    security state *after* the mutation completed, and ``parent_digest``
    is the previous record's ``state_digest`` (or the genesis anchor).
    ``component_digests`` records the per-store digest that ``state_digest``
    was derived from, so a later audit can name which store drifted
    without re-deriving the whole state, and so the chain can be checked
    for self-consistency (``state_digest`` must re-derive from
    ``component_digests``).

    ``epoch`` is the authority-epoch ``(finished, in_flight)`` sample at
    commit time, carried for forensics only: the coherence comparison
    never consults it, because the comparison must be a statement about
    the state digest alone.
    """

    height: int
    parent_digest: str
    state_digest: str
    component_digests: Mapping[str, str] = field(default_factory=dict)
    epoch: Optional[tuple[int, int]] = None
    source: str = ""
    committed_at: float = field(default_factory=time.time)
    genesis: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "height": self.height,
            "parent_digest": self.parent_digest,
            "state_digest": self.state_digest,
            "component_digests": dict(self.component_digests),
            "epoch": (
                [self.epoch[0], self.epoch[1]]
                if self.epoch is not None
                else None
            ),
            "source": self.source,
            "committed_at": self.committed_at,
            "genesis": self.genesis,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "StateCommitRecord":
        epoch = payload.get("epoch")

        if epoch is not None:
            epoch = (int(epoch[0]), int(epoch[1]))

        return cls(
            height=int(payload["height"]),
            parent_digest=str(payload["parent_digest"]),
            state_digest=str(payload["state_digest"]),
            component_digests={
                str(key): str(value)
                for key, value in payload.get(
                    "component_digests", {}
                ).items()
            },
            epoch=epoch,
            source=str(payload.get("source", "")),
            committed_at=float(payload.get("committed_at", 0.0)),
            genesis=bool(payload.get("genesis", False)),
        )


def _validate_label(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise StateCommitError("a state-commit component needs a name")

    if _RESERVED_LABEL_CHARS.intersection(name):
        raise StateCommitError(
            f"component label {name!r} contains a reserved character"
        )


def _jsonable(value: Any) -> str:
    """Deterministic JSON for a reader's canonical output.

    ``sort_keys`` and fixed separators make equivalent state serialize
    identically; a value that cannot be serialised at all is a broken
    reader, which must surface rather than silently hash a ``repr``.
    """

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise StateCommitError(
            f"a state-commit reader produced non-canonical output: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _component_digest(name: str, reader: Callable[[], Any]) -> str:
    """Canonical digest of one component's current state.

    A reader that raises makes the state unreadable, and unreadable is
    not coherent: the exception is wrapped so a caller can distinguish
    "the store cannot be read" from "the store disagrees with the
    journal".
    """

    _validate_label(name)

    try:
        value = reader()
    except Exception as exc:  # noqa: BLE001 - unreadable is incoherent
        raise StateCommitError(
            f"{name} is unreadable: {type(exc).__name__}: {exc}"
        ) from exc

    payload = _jsonable(value)
    return hashlib.sha256(
        (DOMAIN + "\x00" + name + "\x00" + payload).encode("utf-8")
    ).hexdigest()


def _state_digest_from_parts(parts: Mapping[str, str]) -> str:
    canonical = "".join(
        f"{name}={parts[name]};\x1f" for name in sorted(parts)
    )
    return hashlib.sha256(
        (DOMAIN + "\x00" + canonical).encode("utf-8")
    ).hexdigest()


#: Attribute name used to bind a journal to a store, mirroring the
#: ``_authority_epoch`` binding. Stores using ``__slots__`` cannot be
#: bound and :func:`bind_state_commit` reports that.
_ATTRIBUTE = "_state_commit_journal"


def bind_state_commit(component: Any, journal: "StateCommitJournal") -> bool:
    """Attach ``journal`` to an in-domain store whose writes commit state.

    Returns whether the attachment took effect; a component whose class
    leaves no room for the attribute cannot be bound and the caller must
    decide whether that store is reachable from an ALLOW path.

    Rebinding replaces the journal, matching the epoch's shared-store
    semantics: a store shared between two boundaries is committed against
    whichever journal was bound last, which is the coarser guarantee.
    """

    try:
        setattr(component, _ATTRIBUTE, journal)
    except (AttributeError, TypeError):
        return False
    return getattr(component, _ATTRIBUTE, None) is journal


def state_commit_of(
    component: Any,
) -> Optional["StateCommitJournal"]:
    """The journal bound to ``component``, or ``None`` when unbound."""
    journal = getattr(component, _ATTRIBUTE, None)
    return journal if isinstance(journal, StateCommitJournal) else None


@contextmanager
def record_state_commit(
    component: Any,
    source: str,
) -> Iterator[None]:
    """Bracket one in-domain store write so it ends in a commitment.

    An unbound component makes this a pass-through, exactly like
    :func:`firewall.authority_epoch.record_widening`: a store constructed
    standalone has no journal to commit against, and inventing one would
    commit state nobody verifies. A *forgotten* SDK binding therefore
    degrades silently rather than raising, which is why the
    SECURITY_STATE_COHERENCE invariant walks the stores an SDK wires and
    fails on any in-domain store that reaches a write path unbound.

    The commitment is written in a ``finally``, so a write that raised
    half-way -- a torn transition -- still ends with the journal recording
    whatever state resulted. The next authorization sees a head that
    matches the resulting state (if the mutation completed) or one that
    does not (if the process died before the commitment), and in the
    latter case refuses, which is the fail-closed outcome for a crash
    during a state transition.
    """

    journal = state_commit_of(component)
    if journal is None:
        yield
        return

    with journal.mutation(source):
        yield


class StateCommitJournal:
    """Append-only, hash-chained record of the canonical security state.

    The journal is deliberately *not* an authority: it stores digests and
    provenance labels, never permissions, and nothing here can make
    anything be allowed. Its only effect on the boundary is the one this
    module's docstring states -- an allow over state that does not match
    the chain head is refused.

    Two invariants hold of the chain itself:

    * **Append-only and linked.** Every record chains to its predecessor
      by digest, so a record edited in place breaks the link from the
      record that follows it, and a record deleted breaks contiguity.
    * **State-anchored.** ``state_digest`` must re-derive from the
      per-component digests recorded on the same record, so the head
      cannot be rewritten to a value that has nothing behind it.

    ``coherent()`` is the read the ALLOW path performs: it compares the
    live state against the head. Reading and committing share one lock,
    so the snapshot a coherence check sees is a single instant across all
    in-domain stores -- the comparison cannot itself be assembled from
    two different moments.
    """

    __slots__ = (
        "_lock",
        "_components",
        "_epoch_source",
        "_records",
        "_store",
        "_closed",
        "_clock",
    )

    def __init__(
        self,
        *,
        store: Any = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._components: dict[str, Callable[[], Any]] = {}
        self._epoch_source: Optional[Callable[[], tuple[int, int]]] = None
        self._records: list[StateCommitRecord] = []
        self._store = store
        self._closed = False
        self._clock = clock if clock is not None else time.time

        if store is not None:
            loaded = store.load()

            for record in loaded:
                self._records.append(record)

            problems = self.verify_chain()

            if problems:
                raise StateCommitError(
                    "the persisted state-commit chain fails to verify: "
                    + "; ".join(problems)
                )

    # ========================================================
    # Configuration
    # ========================================================

    def attach(
        self,
        name: str,
        reader: Callable[[], Any],
    ) -> None:
        """Register one component of the canonical security state.

        ``reader`` must return a deterministic, JSON-serialisable summary
        of everything about that component an ALLOW decision reads.
        Attaching is idempotent per name; re-attaching replaces the
        reader. Readers are read only under the journal lock.
        """

        _validate_label(name)

        if not callable(reader):
            raise TypeError("a state-commit reader must be callable")

        with self._lock:
            self._components[name] = reader

    def set_epoch_source(
        self,
        source: Optional[Callable[[], tuple[int, int]]],
    ) -> None:
        """Record an epoch sample on future commitments, for forensics."""

        with self._lock:
            self._epoch_source = source

    # ========================================================
    # Digests
    # ========================================================

    def component_digests(self) -> dict[str, str]:
        """Per-component digests of the live state, under the journal lock.

        Raised as :class:`StateCommitError` when a component cannot be
        read; unreadable state is never mistaken for coherent state.
        """

        with self._lock:
            return {
                name: _component_digest(name, reader)
                for name, reader in self._components.items()
            }

    def digest(self) -> str:
        """Canonical digest of the live in-domain security state."""

        return _state_digest_from_parts(self.component_digests())

    # ========================================================
    # Chain
    # ========================================================

    def bootstrap(
        self,
        source: str = "genesis",
    ) -> StateCommitRecord:
        """Seed the chain with the state as it exists right now.

        Called once by the SDK at construction, after every in-domain
        store has been attached and before any write can happen. A chain
        loaded from a persistent store already has its genesis and is left
        untouched: the boot state must then prove itself against the
        recorded head rather than blessing itself.
        """

        with self._lock:
            if self._records:
                return self._records[0]

            parts = self.component_digests()
            record = StateCommitRecord(
                height=0,
                parent_digest=STATE_COMMIT_ANCHOR,
                state_digest=_state_digest_from_parts(parts),
                component_digests=parts,
                epoch=self._sample_epoch_locked(),
                source=source,
                committed_at=self._clock(),
                genesis=True,
            )
            self._append_locked(record)
            return record

    def commit(
        self,
        source: str,
    ) -> Optional[StateCommitRecord]:
        """Append a commitment for the current state, if it changed.

        Returns ``None`` when the state is unchanged since the chain head
        -- a write that mutated nothing, or a re-entrant bracket around a
        change another bracket already committed -- because an unchanged
        state needs no new link. The chain therefore records exactly the
        state transitions, and a record is evidence that a transition
        happened.
        """

        with self._lock:
            if not self._records:
                self.bootstrap(source="genesis")

            head = self._records[-1]
            parts = self.component_digests()
            state_digest = _state_digest_from_parts(parts)

            if state_digest == head.state_digest:
                return None

            record = StateCommitRecord(
                height=head.height + 1,
                parent_digest=head.state_digest,
                state_digest=state_digest,
                component_digests=parts,
                epoch=self._sample_epoch_locked(),
                source=source,
                committed_at=self._clock(),
                genesis=False,
            )
            self._append_locked(record)
            return record

    def _sample_epoch_locked(self) -> Optional[tuple[int, int]]:
        if self._epoch_source is None:
            return None

        try:
            return self._epoch_source()
        except Exception:  # noqa: BLE001 - forensics only
            return None

    def _append_locked(self, record: StateCommitRecord) -> None:
        self._records.append(record)

        if self._store is not None:
            self._store.insert(record)

    # ========================================================
    # Read side
    # ========================================================

    def coherent(self) -> tuple[bool, str]:
        """Whether the live state is exactly what the chain head records.

        Returns ``(ok, reason)``. ``ok`` is true only when the chain is
        non-empty and the live digest equals the head's digest; when it is
        false the reason names the components that drifted, so an operator
        (or the SECURITY_STATE_COHERENCE invariant) can see which store no
        longer matches the firewall's own record of itself.
        """

        with self._lock:
            problems = self.verify_chain()

            if problems:
                return (
                    False,
                    "the commitment chain is broken: "
                    + "; ".join(problems[:3]),
                )

            if not self._records:
                return False, "no state commitment exists yet"

            live_parts = self.component_digests()
            live_digest = _state_digest_from_parts(live_parts)
            head = self._records[-1]

            if live_digest == head.state_digest:
                return True, ""

            drifted = [
                name
                for name, digest in live_parts.items()
                if head.component_digests.get(name) != digest
            ]

            if drifted:
                return (
                    False,
                    "live state differs from the committed head in "
                    + ", ".join(sorted(drifted)),
                )

            return False, "live state differs from the committed head"

    def verify_chain(self) -> tuple[str, ...]:
        """Every link of the chain, as a list of problems (empty = sound).

        Checks, in order: the genesis record exists at height 0 and chains
        from the anchor; heights are exactly ``0..n-1``; every record's
        parent digest equals its predecessor's state digest; and every
        record's state digest re-derives from the component digests it
        records. A chain that fails any of these is not a chain -- it is a
        list of records, and state attested by it proves nothing.
        """

        problems: list[str] = []

        if not self._records:
            return tuple(problems)

        first = self._records[0]

        if first.height != 0 or not first.genesis:
            problems.append(
                "the first record is not a genesis record at height 0"
            )

        if first.parent_digest != STATE_COMMIT_ANCHOR:
            problems.append(
                "the genesis record does not chain from the anchor"
            )

        for index, record in enumerate(self._records):
            if record.height != index:
                problems.append(
                    f"record at index {index} has height {record.height}, "
                    "so the chain is not contiguous"
                )

            if index > 0:
                expected = self._records[index - 1].state_digest

                if record.parent_digest != expected:
                    problems.append(
                        f"record {index} does not chain from record "
                        f"{index - 1}"
                    )

            expected_digest = _state_digest_from_parts(
                record.component_digests
            )

            if record.state_digest != expected_digest:
                problems.append(
                    f"record {index} state digest does not re-derive from "
                    "its recorded components"
                )

            if not record.component_digests and not record.genesis:
                problems.append(
                    f"record {index} carries no component digests"
                )

        return tuple(problems)

    @contextmanager
    def mutation(self, source: str) -> Iterator[None]:
        """Bracket one in-domain mutation so it ends in a commitment.

        The journal lock is held for the whole body, which is what makes a
        later ``coherent()`` a snapshot of a single instant: no write to
        any attached store can interleave a digest read. On exit the
        resulting state is committed (or confirmed unchanged).

        A commitment failure on the way out of a body that *already*
        raised is suppressed rather than allowed to replace the original
        error -- the mutation's own failure is the primary signal, and the
        stale head it leaves behind is caught by the next coherence check,
        which is the fail-closed outcome. A commitment failure on a clean
        exit is raised: the write happened and the journal could not say
        so, which is exactly a torn transition.
        """

        raised = False

        with self._lock:
            try:
                yield
            except BaseException:
                raised = True
                raise
            finally:
                try:
                    self.commit(source)
                except Exception:  # noqa: BLE001 - see docstring
                    if not raised:
                        raise

    # ========================================================
    # Accessors
    # ========================================================

    def head(self) -> Optional[StateCommitRecord]:
        with self._lock:
            return self._records[-1] if self._records else None

    def height(self) -> int:
        with self._lock:
            return len(self._records) - 1 if self._records else -1

    def records(self) -> tuple[StateCommitRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._components))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return

            self._closed = True

            if self._store is not None:
                self._store.close()

    def __enter__(self) -> "StateCommitJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ========================================================
# Canonical readers for the in-domain stores
# ========================================================
#
# Each reader returns the *whole* of the store's content that an ALLOW
# decision can read, as a deterministic JSON-serialisable value. Keeping
# the readers here rather than as methods on the stores means a store has
# no digest logic of its own -- it only opens brackets -- and the domain
# is defined in one place where the invariant can cite it.


def revocation_reader(registry: Any) -> tuple[tuple[Any, ...], ...]:
    """Every revocation record, sorted and projected to plain values.

    ``revoked_at`` is part of the state: a record revoked at ``t1`` is
    not the same state as one revoked at ``t2``, and a rollback that
    restores an older timestamp is exactly the kind of replay this module
    exists to catch.
    """

    records = registry.records()
    return tuple(
        sorted(
            (
                record.fingerprint,
                float(record.revoked_at),
                str(record.reason),
            )
            for record in records
        )
    )


def issuer_trust_reader(store: Any) -> tuple[str, ...]:
    """The trusted-issuer set, as read by the boundary's gate.

    ``trusted_issuers()`` already subtracts revoked issuers, so a silent
    un-revocation of a trusted name -- the dangerous direction -- moves
    this value, while an untrusted name's revocation state cannot affect
    any gate and need not move it.
    """

    return tuple(sorted(str(name) for name in store.trusted_issuers()))


def lineage_reader(lineage: Any) -> tuple[tuple[str, str], ...]:
    """Every registered edge, sorted by child fingerprint."""

    records = lineage.snapshot()
    return tuple(
        sorted(
            (str(record.child_fingerprint), str(record.parent_fingerprint))
            for record in records
        )
    )
