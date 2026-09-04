"""A monotonic count of control-plane writes that can widen authority.

Why this exists
---------------

:meth:`firewall.sdk.FirewallSDK.authorize` is a conjunction over eleven
gates, and each gate reads its own security state at its own instant.
Nothing held those eleven reads to a single point in time, so a verdict
could reflect a combination of values that no instant ever had::

    t0   an Aegis suspension is live; the issuer is trusted
    t1   _gate_issuer reads "trusted"                        -> passes
    t2   revoke_issuer(...)  completes
    t3   aegis.lift(...)     completes
    t4   _gate_aegis reads "no restriction"                  -> passes
    t5   authorize() returns allowed=True

Every ordering of the request against those two writes that respects the
order the writes actually happened in -- t2 before t3 -- denies:

    request, revoke, lift    the suspension was live         -> deny
    revoke, request, lift    the issuer was untrusted        -> deny
    revoke, lift, request    the issuer was untrusted        -> deny

So the allow at t5 corresponds to no serialization at all. This is worse
than a stale allow: staleness is still explainable by an earlier
linearization point, and there is no point in time -- earlier, later, or
during -- at which the state permitted this request. The allow was
assembled out of two different moments.

The argument that fails, and the one that holds
-----------------------------------------------

If every control-plane write only ever *narrowed* authority, sampling the
gate inputs at different instants would be sound. Gate ``k`` passing at
``t_k`` implies its input was permissive at ``t_k``; monotone narrowing
carries that backwards to ``t_0``; so every input was permissive at
``t_0``, ``t_0`` is a valid linearization point, and the allow is correct.

That argument breaks on exactly one thing: a write that widens. So what
is counted here is not state and not time -- it is the number of writes
that invalidate the proof. ``authorize()`` reads the count before its
first gate and again before it returns an allow. Unequal means the proof
does not cover this execution, and an allow the proof does not cover is
refused.

What this is not
----------------

It is not an authorization path and cannot become one. Comparing two
epochs has exactly one possible effect -- turning an allow into a denial.
No value of the counter causes anything to be permitted, so a forged,
frozen, or maliciously reset counter cannot manufacture authority. It can
only fail to *catch* a widening, which is the pre-v2.6 behaviour rather
than a new exposure. That asymmetry is the whole safety argument for
adding a mutable global to the boundary, and it is why the counter is
never read as evidence, never recorded as a permission, and never
consulted to decide that a gate can be skipped.

It is not a version number for security state. It reports that a widening
write happened, not what state resulted. Deciding what the new state
permits stays with the gates -- which is why the response to a moved epoch
is to refuse, not to re-derive a verdict from the count.

It is not a lock, and it does not make ``authorize()`` atomic. Two
requests still interleave freely, and a widening write still lands
whenever it lands. The claim is narrower: an allow that survives implies
no widening write completed during it, and therefore implies the first
gate's instant is a valid linearization point for the whole conjunction.

It is deliberately coarse. One counter covers every capability and every
agent, so a widening write for an unrelated agent invalidates in-flight
requests that it could not have affected. That is a false denial, not a
false allow, and it buys the property that no widening write can be
*missed* because someone mis-attributed it to the wrong scope. Precision
here would mean deciding, outside the gates, which widenings are
irrelevant to a given request -- exactly the reasoning this module exists
to stop trusting.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Iterator, NamedTuple, Optional

__all__ = [
    "AuthorityEpoch",
    "EPOCH_BRACKET_HELPERS",
    "EPOCH_DIVERGENCE_PREFIXES",
    "EPOCH_MEASUREMENT_BRACKETS",
    "EpochSample",
    "WIDENING_WRITES",
    "bind_epoch",
    "epoch_of",
    "is_epoch_denial",
    "record_widening",
]

#: Names that open an epoch interval, as they appear at a call site.
#:
#: The AUTHORITY_EPOCH_COVERAGE invariant reads source text, so it has to
#: recognise a bracket syntactically. ``record_widening`` is the form a
#: store uses; ``widening`` is the form the boundary uses when it already
#: holds the epoch (``self.authority_epoch.widening(...)``).
EPOCH_BRACKET_HELPERS = frozenset({"record_widening", "widening"})

#: Every write in the package that can widen authority, and therefore
#: must open an epoch interval.
#:
#: This is a census, not a description: the AUTHORITY_EPOCH_COVERAGE
#: invariant checks it in **both** directions. A function listed here
#: without a bracket is a violation, and a bracket in a function not
#: listed here is also a violation. The second direction is the one that
#: matters over time -- it means a later change cannot quietly add a
#: widening path and satisfy the invariant by bracketing it, because the
#: census is where the claim "these are all of them" is recorded, and a
#: reviewer has to touch this literal to make the check pass.
#:
#: Deliberately absent, each because no canonical gate reads the value it
#: changes:
#:
#: - ``RevocationRegistry`` has no un-revoke; revocation is terminal.
#: - ``LifecycleStore``/``ReplayStore``/``KeyManager`` only ever add used
#:   nonces, spent capabilities and retired keys -- every write narrows.
#: - ``AegisController.register``/``grant`` narrow: they make ``tracked()``
#:   true, which subjects a fingerprint to *more* checks, not fewer.
#: - ``configure_delegation_budget`` raises a ceiling that no gate reads.
#:   ``authorize_with_delegation_budget`` runs the whole chain and *then*
#:   reserves atomically, so bracketing it would produce denials over a
#:   value the epoch's window never covered.
WIDENING_WRITES = frozenset(
    {
        ("firewall/aegis/restriction.py", "RestrictionStore.lift"),
        ("firewall/aegis/restriction.py", "RestrictionStore.clear"),
        ("firewall/key_management.py", "IssuerTrustStore.trust"),
        ("firewall/refusal_state.py", "RefusalState.clear"),
        ("firewall/refusal_state.py", "RefusalState.clear_all"),
        ("firewall/risk_context.py", "RiskContext.reset"),
        ("firewall/security_context.py", "SecurityContext.reset"),
        ("firewall/semantic_chain.py", "SemanticChainContext.reset"),
        ("firewall/sdk.py", "FirewallSDK.max_delegation_depth"),
        ("firewall/sdk.py", "FirewallSDK.set_security_context"),
        ("firewall/sdk.py", "FirewallSDK.set_semantic_context"),
        ("firewall/sdk.py", "FirewallSDK.set_risk_context"),
    }
)

#: Epoch brackets that are not widening writes, because nothing they
#: bracket is authority.
#:
#: The census direction that catches an unbracketed widening also flags
#: *any* bracket outside the census, and that is the behaviour worth
#: keeping -- but it means a bracket opened for a third reason needs
#: somewhere to be declared. The measurement harness is that third
#: reason: :mod:`firewall.benchmarks` drives this module's primitives to
#: time them, on epochs it constructs itself, reachable from no gate.
#:
#: Listed rather than exempted by module, and checked in both directions
#: like :data:`WIDENING_WRITES`, so the list cannot rot into a blind spot:
#: an entry that no longer brackets is a finding, and a benchmark that
#: starts widening a real store has to be moved into the census above
#: rather than inheriting an exemption its neighbours were given.
#:
#: To qualify, a function must construct the epoch it brackets. Bracketing
#: an epoch some SDK also samples is a widening write no matter what the
#: function is named.
EPOCH_MEASUREMENT_BRACKETS = frozenset(
    {
        ("firewall/benchmarks.py", "benchmark_epoch_primitives"),
        ("firewall/benchmarks.py", "benchmark_epoch_contention"),
    }
)

#: The denial-reason prefixes :meth:`EpochSample.divergence` can produce.
#:
#: Declared so that a caller partitioning verdicts by cause -- the
#: ``authorize_under_widening`` benchmark, an operator's dashboard -- can
#: ask whether a denial came from the epoch without embedding three
#: literals. The three forms are not interchangeable and the distinction is
#: worth keeping: ``widened_during_authorization`` means a write finished
#: inside the request, while the two ``in_flight`` forms mean one was still
#: running at an end of the window. Only the first can be attributed to a
#: completed write.
EPOCH_DIVERGENCE_PREFIXES = frozenset(
    {
        "widened_during_authorization",
        "widening_in_flight_at_entry",
        "widening_in_flight_at_commit",
    }
)


def is_epoch_denial(reason: str) -> bool:
    """Whether ``reason`` names an epoch divergence.

    Prefix matching against :data:`EPOCH_DIVERGENCE_PREFIXES`, because each
    form carries a source label and a count after its prefix. Nothing
    branches on the answer inside the authorization path -- this is for
    callers classifying a verdict after the fact, and a classifier that
    could turn a denial into an allow would be a second authorization path.
    """
    return any(
        reason.startswith(prefix) for prefix in EPOCH_DIVERGENCE_PREFIXES
    )


class EpochSample(NamedTuple):
    """One observation of an :class:`AuthorityEpoch`.

    ``source`` is diagnostic only. It never takes part in the comparison,
    because the comparison must be a statement about counts alone -- a
    label is the kind of thing that gets reused or left stale, and this is
    not a place to make correctness depend on one.
    """

    finished: int
    in_flight: int
    source: str

    def covers(self, later: "EpochSample") -> bool:
        """Whether an allow spanning these two samples is serializable.

        True requires both that no widening write finished between them and
        that none was in flight at either end. The first rules out a write
        contained inside the request; the second rules out one that spans
        either boundary, which is the case a bare counter cannot see.
        """
        return (
            self.finished == later.finished
            and self.in_flight == 0
            and later.in_flight == 0
        )

    def divergence(self, later: "EpochSample") -> str:
        """A denial-reason suffix naming why :meth:`covers` failed.

        Every prefix returned here is listed in
        :data:`EPOCH_DIVERGENCE_PREFIXES`, so a caller partitioning verdicts
        by cause can recognise an epoch denial without copying literals out
        of this function -- and adding a fourth form without declaring it
        fails ``test_every_divergence_form_is_declared`` rather than
        quietly landing in somebody's "other" bucket.
        """
        if later.finished != self.finished:
            moved = later.finished - self.finished
            return f"widened_during_authorization:{later.source or '?'}:{moved}"
        if self.in_flight:
            return f"widening_in_flight_at_entry:{self.source or '?'}"
        if later.in_flight:
            return f"widening_in_flight_at_commit:{later.source or '?'}"
        return ""


class AuthorityEpoch:
    """Counts control-plane writes that could widen authority.

    A sample is a pair: how many widening writes have *finished*, and how
    many are *in flight*. Both halves are load-bearing, and the reason is
    that a single monotonic counter cannot express the property.

    Let a request read the counter at ``t_0`` and again at ``t_f``, and let
    a widening write mutate its store at ``t_m`` and bump the counter at
    ``t_b``. The request's gate reads all fall inside ``(t_0, t_f)``, so
    the dangerous case -- some gates reading pre-mutation state and others
    reading post-mutation state -- is exactly ``t_0 < t_m < t_f``, and
    catching it requires ``t_0 < t_b < t_f``.

    Bumping after the mutation gives ``t_m < t_b``, which leaves
    ``t_m < t_f < t_b``: the request observed the widened store and
    finished before the bump. Bumping before it gives ``t_b < t_m``, which
    leaves ``t_b < t_0 < t_m``: both samples agree, and the gates straddle
    the mutation anyway. Bumping on both sides still leaves the case where
    a slow write's two bumps land outside a fast request's two samples.
    One counter cannot do it, because one counter cannot say "a write is
    happening right now".

    So a widening write is an interval, not an instant. It is announced on
    entry, and the request refuses if any write was in flight at either
    sample -- which covers every write that spans a sample -- or if the
    finished count moved, which covers every write contained between them.

    There is no setter and no reset. A caller able to move the finished
    count backwards could make a widened state look unwidened, and that is
    the one failure this class must not permit.
    """

    __slots__ = ("_lock", "_finished", "_in_flight", "_last_source")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._finished = 0
        self._in_flight = 0
        self._last_source = ""

    def sample(self) -> "EpochSample":
        """Return the current (finished, in-flight) pair.

        A widening that begins immediately after this returns is the case
        the second sample exists to catch, so no attempt is made to make
        the sample and the work that follows it atomic.
        """
        with self._lock:
            return EpochSample(self._finished, self._in_flight, self._last_source)

    @contextmanager
    def widening(self, source: str) -> Iterator[None]:
        """Bracket one authority-widening write.

        The write is in flight for the whole body, so a request sampling at
        any instant inside it refuses. ``source`` is a diagnostic label
        carried into the denial reason so an operator can see which write
        invalidated the request; nothing branches on its value.

        The finished count increments even when the body raises. A store
        that failed halfway through a widening may have widened partly, and
        counting the attempt denies in-flight requests that could have seen
        the partial result. Counting only successes would leave exactly
        that case uncovered, which is the wrong direction to be wrong in.
        """
        with self._lock:
            self._in_flight += 1
            self._last_source = source
        try:
            yield
        finally:
            with self._lock:
                self._in_flight -= 1
                self._finished += 1
                self._last_source = source

    def widen(self, source: str) -> None:
        """Record a widening write that is already complete.

        For call sites where the mutation cannot be bracketed -- it happened
        inside a callee that returned, and wrapping it would mean holding
        the interval open across unrelated work. Equivalent to an
        instantaneous :meth:`widening`, and carries that form's hole: a
        request whose second sample falls between the mutation and this
        call is not caught. Prefer :meth:`widening` wherever the mutation
        can be enclosed.
        """
        with self._lock:
            self._finished += 1
            self._last_source = source


_ATTRIBUTE = "_authority_epoch"


def bind_epoch(component: Any, epoch: AuthorityEpoch) -> bool:
    """Attach ``epoch`` to a store whose widening writes must be counted.

    Returns whether the attachment took effect. A component using
    ``__slots__`` without room for the attribute cannot be bound, and
    saying so lets the caller fail loudly instead of silently losing the
    count.

    Rebinding is allowed and replaces the epoch. That is how a store shared
    between two SDKs ends up counted by the second one only, so callers
    that share stores across boundaries get the coarser guarantee: writes
    are counted once, against whichever epoch is bound.
    """
    try:
        setattr(component, _ATTRIBUTE, epoch)
    except (AttributeError, TypeError):
        return False
    return getattr(component, _ATTRIBUTE, None) is epoch


def epoch_of(component: Any) -> Optional[AuthorityEpoch]:
    """Return the epoch bound to ``component``, or ``None`` if unbound."""
    epoch = getattr(component, _ATTRIBUTE, None)
    return epoch if isinstance(epoch, AuthorityEpoch) else None


@contextmanager
def record_widening(component: Any, source: str) -> Iterator[None]:
    """Bracket a widening write on ``component``, if it has an epoch.

    An unbound component makes this a pass-through. That is the honest
    behaviour for a store constructed standalone -- there is no epoch to
    count against, and inventing one would count writes nobody samples --
    but it does mean a *forgotten* binding degrades silently to pre-v2.6
    behaviour rather than raising. Which bindings are required is therefore
    not left to review: it is asserted by the ``AUTHORITY_EPOCH_COVERAGE``
    invariant, which walks the stores an SDK wires and fails on any that
    reaches a widening path unbound.
    """
    epoch = epoch_of(component)
    if epoch is None:
        yield
        return
    with epoch.widening(source):
        yield
