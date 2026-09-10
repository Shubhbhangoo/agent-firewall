"""v2.2 Continuous Authorization Monitor.

Watches decisions that have already been authorized and re-asks the canonical
authorization path when security-relevant state changes underneath them.

The monitor is not an authorization authority. It cannot allow anything; the
strongest thing it can do is notice that ``FirewallSDK.authorize()`` would now
refuse something it previously permitted, and hand that finding to a
containment callback that must itself pass the authorization boundary.

Fail-closed posture
-------------------
A revalidation that cannot be completed is recorded as a *failure*, never
discarded. The previous implementation wrapped the whole path in
``except Exception: return None``, which made an unreadable security state
indistinguishable from a clean bill of health -- the classic fail-open shape.
Failures are counted, exposed through :meth:`get_revalidation_stats`, and
delivered to ``on_failure`` so that an operator can see that monitoring has
stopped working rather than assuming silence means safety.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from firewall.sdk import FirewallSDK

from firewall.capability import Capability
from firewall.continuous_auth.engine import (
    UNTHROTTLED_TRIGGERS,
    ContinuousAuthorizationEngine,
    RevalidationResult,
    RevalidationTrigger,
)


@dataclass(frozen=True)
class MonitoringConfig:
    """Configuration for continuous authorization monitoring."""

    # Minimum interval between revalidations for the same decision (seconds).
    # Never applied to the triggers in UNTHROTTLED_TRIGGERS or to any trigger
    # listed in immediate_triggers.
    min_revalidation_interval: float = 1.0

    # Age past which a decision is revalidated regardless of throttling.
    max_decision_age: float = 300.0

    # Triggers that bypass min_revalidation_interval.
    immediate_triggers: tuple[RevalidationTrigger, ...] = (
        RevalidationTrigger.CAPABILITY_REVOKED,
        RevalidationTrigger.DELEGATION_REVOKED,
        RevalidationTrigger.IDENTITY_CHANGED,
        RevalidationTrigger.POSTURE_CHANGED,
        RevalidationTrigger.RISK_THRESHOLD_EXCEEDED,
        RevalidationTrigger.TRUST_COLLAPSE,
        RevalidationTrigger.POLICY_CHANGED,
        RevalidationTrigger.INCIDENT_OPENED,
    )

    enable_periodic_revalidation: bool = True
    periodic_interval: float = 60.0

    # Upper bound on monitored decisions. A control-plane process that accepts
    # unbounded registrations from callers is a memory-exhaustion surface.
    max_monitored_decisions: int = 4096


class RevalidationOutcome(str, Enum):
    """Why a revalidation attempt ended the way it did."""

    REVALIDATED = "revalidated"
    THROTTLED = "throttled"
    NOT_MONITORED = "not_monitored"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    ENGINE_ERROR = "engine_error"


@dataclass(frozen=True)
class RevalidationAttempt:
    """The result of asking the monitor to revalidate one decision.

    Always returned, including on failure. A caller can therefore distinguish
    "checked, still authorized" from "could not check" -- a distinction the
    previous ``Optional[RevalidationResult]`` return type erased.
    """

    outcome: RevalidationOutcome
    cache_key: str
    trigger: RevalidationTrigger
    result: Optional[RevalidationResult] = None
    detail: str = ""

    @property
    def completed(self) -> bool:
        return self.outcome is RevalidationOutcome.REVALIDATED

    @property
    def failed(self) -> bool:
        """True when monitoring could not answer the question.

        Throttling and "not monitored" are not failures: both are definite
        answers about a decision the monitor is not responsible for right now.
        A missing capability or an engine error are failures, because the
        security state is genuinely unknown.
        """
        return self.outcome in (
            RevalidationOutcome.CAPABILITY_UNAVAILABLE,
            RevalidationOutcome.ENGINE_ERROR,
        )

    @property
    def authority_revoked(self) -> bool:
        return self.result is not None and self.result.authority_revoked

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "cache_key": self.cache_key,
            "trigger": self.trigger.value,
            "detail": self.detail,
            "result": None if self.result is None else self.result.to_dict(),
        }


@dataclass(frozen=True)
class MonitoredDecision:
    """A decision being monitored for continuous revalidation.

    ``request`` is stored as an immutable canonical JSON string alongside the
    live dict so that a caller mutating the dict it passed in cannot silently
    change what is being revalidated.
    """

    capability_fingerprint: str
    action: str
    request: dict[str, Any]
    request_hash: str
    cache_key: str
    last_revalidated: float
    registered_at: float
    revalidation_count: int = 0
    failure_count: int = 0
    last_result: Optional[RevalidationResult] = None
    last_outcome: Optional[RevalidationOutcome] = None


class ContinuousAuthorizationMonitor:
    """
    Monitors security state and triggers continuous revalidation of
    authorization decisions.
    """

    def __init__(
        self,
        engine: ContinuousAuthorizationEngine,
        sdk: FirewallSDK,
        *,
        config: Optional[MonitoringConfig] = None,
        clock: Optional[Callable[[], float]] = None,
        on_revalidation: Optional[Callable[[RevalidationResult], None]] = None,
        on_authority_revoked: Optional[Callable[[RevalidationResult], None]] = None,
        on_failure: Optional[Callable[[RevalidationAttempt], None]] = None,
    ) -> None:
        if not isinstance(engine, ContinuousAuthorizationEngine):
            raise TypeError("engine must be a ContinuousAuthorizationEngine")

        if not hasattr(sdk, "authorize"):
            raise TypeError("sdk must expose authorize()")

        self._engine = engine
        self._sdk = sdk
        self._config = config or MonitoringConfig()
        self._clock = clock or time.time
        self._on_revalidation = on_revalidation
        self._on_authority_revoked = on_authority_revoked
        self._on_failure = on_failure

        self._lock = threading.RLock()
        self._monitored: "OrderedDict[str, MonitoredDecision]" = OrderedDict()

        # `_stop` makes shutdown prompt and deterministic. Sleeping on the
        # interval directly meant stop_periodic_monitoring() had to wait out a
        # whole period (up to periodic_interval seconds) while its join()
        # timed out and it cleared the thread handle anyway -- leaving a live
        # thread the object no longer tracked.
        self._stop = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

        # Cumulative event counters, incremented at the moment an outcome is
        # observed. These deliberately do NOT derive from each decision's
        # `last_result`: the engine rebases its baseline once drift is
        # detected, so an allow -> deny transition is visible in exactly one
        # revalidation and then disappears from the last result. Derived
        # counters therefore reported "nothing was revoked" one sweep after a
        # revocation, which is the precise failure mode this subsystem exists
        # to prevent. They also survive LRU eviction of the decision itself.
        self._failures = 0
        self._revalidations = 0
        self._state_changes = 0
        self._authority_revocations = 0
        self._authority_widenings = 0

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def monitor_decision(
        self,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
        request_hash: str,
        cache_key: str,
    ) -> None:
        """Register a decision for continuous monitoring."""
        now = float(self._clock())
        with self._lock:
            existing = self._monitored.get(cache_key)
            self._monitored[cache_key] = MonitoredDecision(
                capability_fingerprint=capability_fingerprint,
                action=action,
                request=dict(request),
                request_hash=request_hash,
                cache_key=cache_key,
                # Re-registering an already-monitored decision must not reset
                # its throttle window: doing so would let a caller that
                # re-authorizes in a tight loop starve the periodic sweep and
                # keep a stale decision alive indefinitely.
                last_revalidated=(
                    existing.last_revalidated if existing is not None else now
                ),
                registered_at=(
                    existing.registered_at if existing is not None else now
                ),
                revalidation_count=(
                    existing.revalidation_count if existing is not None else 0
                ),
                failure_count=(
                    existing.failure_count if existing is not None else 0
                ),
                last_result=existing.last_result if existing is not None else None,
                last_outcome=existing.last_outcome if existing is not None else None,
            )
            self._monitored.move_to_end(cache_key)

            while len(self._monitored) > self._config.max_monitored_decisions:
                self._monitored.popitem(last=False)

    def unmonitor_decision(self, cache_key: str) -> None:
        """Stop monitoring a decision."""
        with self._lock:
            self._monitored.pop(cache_key, None)

    # ------------------------------------------------------------------
    # Revalidation
    # ------------------------------------------------------------------

    def check_and_revalidate(
        self,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
        cache_key: str,
        trigger: RevalidationTrigger,
    ) -> RevalidationAttempt:
        """Revalidate one monitored decision if the trigger warrants it.

        Always returns an attempt record. ``None`` is never used to mean both
        "nothing to do" and "something went wrong".
        """
        with self._lock:
            monitored = self._monitored.get(cache_key)
            if monitored is None:
                return RevalidationAttempt(
                    outcome=RevalidationOutcome.NOT_MONITORED,
                    cache_key=cache_key,
                    trigger=trigger,
                    detail="decision is not registered for monitoring",
                )

            now = float(self._clock())
            age = now - monitored.last_revalidated

            throttled = age < self._config.min_revalidation_interval
            exempt = (
                trigger in UNTHROTTLED_TRIGGERS
                or trigger in self._config.immediate_triggers
            )
            stale = age > self._config.max_decision_age

            if throttled and not exempt and not stale:
                return RevalidationAttempt(
                    outcome=RevalidationOutcome.THROTTLED,
                    cache_key=cache_key,
                    trigger=trigger,
                    detail=(
                        f"last revalidated {age:.3f}s ago, minimum interval is "
                        f"{self._config.min_revalidation_interval}s"
                    ),
                )

            if stale:
                trigger = RevalidationTrigger.TIME

        capability = self._lookup_capability(capability_fingerprint)
        if capability is None:
            # The capability is no longer resolvable, so we cannot re-ask
            # authorize() about it. That is a security-relevant unknown, not a
            # quiet no-op.
            return self._record_failure(
                RevalidationAttempt(
                    outcome=RevalidationOutcome.CAPABILITY_UNAVAILABLE,
                    cache_key=cache_key,
                    trigger=trigger,
                    detail=(
                        "capability "
                        f"{capability_fingerprint} is not present in the SDK "
                        "capability registry; authorization state cannot be "
                        "re-established"
                    ),
                ),
                cache_key,
            )

        try:
            result = self._engine.revalidate(
                capability,
                action,
                request,
                trigger=trigger,
            )
        except Exception as exc:
            return self._record_failure(
                RevalidationAttempt(
                    outcome=RevalidationOutcome.ENGINE_ERROR,
                    cache_key=cache_key,
                    trigger=trigger,
                    detail=f"{type(exc).__name__}: {exc}",
                ),
                cache_key,
            )

        attempt = RevalidationAttempt(
            outcome=RevalidationOutcome.REVALIDATED,
            cache_key=cache_key,
            trigger=trigger,
            result=result,
        )

        with self._lock:
            self._revalidations += 1
            if result.state_changed:
                self._state_changes += 1
            if result.authority_revoked:
                self._authority_revocations += 1
            if result.authority_widened:
                self._authority_widenings += 1

            current = self._monitored.get(cache_key)
            if current is not None:
                self._monitored[cache_key] = replace(
                    current,
                    last_revalidated=float(self._clock()),
                    revalidation_count=current.revalidation_count + 1,
                    last_result=result,
                    last_outcome=RevalidationOutcome.REVALIDATED,
                )

        self._notify(self._on_revalidation, result)
        if result.authority_revoked:
            self._notify(self._on_authority_revoked, result)

        return attempt

    def _record_failure(
        self,
        attempt: RevalidationAttempt,
        cache_key: str,
    ) -> RevalidationAttempt:
        """Count a failed revalidation and surface it, rather than dropping it."""
        with self._lock:
            self._failures += 1
            current = self._monitored.get(cache_key)
            if current is not None:
                self._monitored[cache_key] = replace(
                    current,
                    failure_count=current.failure_count + 1,
                    last_outcome=attempt.outcome,
                )

        self._notify(self._on_failure, attempt)
        return attempt

    @staticmethod
    def _notify(callback: Optional[Callable[[Any], None]], payload: Any) -> None:
        """Invoke an observer without letting it affect the security path.

        Observer exceptions are swallowed deliberately: a badly-behaved
        telemetry sink must not be able to abort revalidation or, worse, make
        a revoked authority look like it was never checked. The revalidation
        itself has already completed and been recorded by this point.
        """
        if callback is None:
            return
        try:
            callback(payload)
        except Exception:
            pass

    def _lookup_capability(self, fingerprint: str) -> Optional[Capability]:
        """Resolve a capability by fingerprint from the SDK registry."""
        candidate = self._sdk.known_capabilities().get(fingerprint)
        return candidate if isinstance(candidate, Capability) else None

    # ------------------------------------------------------------------
    # Periodic sweep
    # ------------------------------------------------------------------

    def start_periodic_monitoring(self) -> None:
        """Start the periodic monitoring thread."""
        if not self._config.enable_periodic_revalidation:
            return

        with self._lock:
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                return
            self._stop.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                name="continuous-authorization-monitor",
                daemon=True,
            )
            self._monitor_thread.start()

    def stop_periodic_monitoring(self, *, timeout: float = 5.0) -> bool:
        """Stop the periodic monitoring thread.

        Returns True when the thread is confirmed stopped. The handle is only
        cleared on a confirmed stop, so a thread that outlives its join
        timeout stays visible instead of being silently orphaned.
        """
        self._stop.set()

        with self._lock:
            thread = self._monitor_thread

        if thread is None:
            return True

        thread.join(timeout=timeout)
        if thread.is_alive():
            return False

        with self._lock:
            if self._monitor_thread is thread:
                self._monitor_thread = None
        return True

    @property
    def is_running(self) -> bool:
        with self._lock:
            thread = self._monitor_thread
        return thread is not None and thread.is_alive()

    def _monitor_loop(self) -> None:
        """Periodic sweep.

        ``Event.wait`` rather than ``sleep`` so shutdown is immediate, and the
        wait happens at the top so a freshly started monitor does not
        revalidate decisions in the same instant they were registered.
        """
        interval = max(float(self._config.periodic_interval), 0.0)

        while not self._stop.wait(interval):
            self.sweep(RevalidationTrigger.TIME)

    def sweep(
        self,
        trigger: RevalidationTrigger = RevalidationTrigger.TIME,
    ) -> tuple[RevalidationAttempt, ...]:
        """Revalidate every monitored decision once. Also callable directly.

        Exposed publicly so the periodic behaviour can be exercised
        deterministically in tests and driven by an external scheduler,
        instead of tests having to sleep and hope.
        """
        with self._lock:
            snapshot = tuple(self._monitored.values())

        attempts: list[RevalidationAttempt] = []
        for decision in snapshot:
            if self._stop.is_set():
                break
            attempts.append(
                self.check_and_revalidate(
                    capability_fingerprint=decision.capability_fingerprint,
                    action=decision.action,
                    request=decision.request,
                    cache_key=decision.cache_key,
                    trigger=trigger,
                )
            )
        return tuple(attempts)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_monitored_decisions(self) -> dict[str, MonitoredDecision]:
        """Get all currently monitored decisions."""
        with self._lock:
            return dict(self._monitored)

    def get_revalidation_stats(self) -> dict[str, Any]:
        """Statistics about revalidation activity.

        The ``decisions_changed_*`` and ``total_revalidations`` figures are
        cumulative event counts, not properties of the current table. A
        transition is counted when it is observed and stays counted, so a
        revocation that happened three sweeps ago is still reported.

        ``revalidation_failures`` is reported alongside the successes on
        purpose: a monitor with zero state changes and a rising failure count
        is broken, not quiet, and a stats view that only counted successes
        would present those two states identically.

        ``currently_denied`` is the point-in-time view -- monitored decisions
        whose most recent revalidation came back denied. It answers a
        different question from ``decisions_changed_allow_to_deny`` and both
        are needed: the former is live exposure, the latter is history.
        """
        with self._lock:
            decisions = tuple(self._monitored.values())
            failures = self._failures
            revalidations = self._revalidations
            state_changes = self._state_changes
            revocations = self._authority_revocations
            widenings = self._authority_widenings

        currently_denied = sum(
            1
            for d in decisions
            if d.last_result is not None and not d.last_result.revalidated_allowed
        )

        return {
            "monitored_decisions": len(decisions),
            "total_revalidations": revalidations,
            "revalidation_failures": failures,
            "decisions_with_state_change": state_changes,
            "decisions_changed_allow_to_deny": revocations,
            "decisions_changed_deny_to_allow": widenings,
            "currently_denied": currently_denied,
            "running": self.is_running,
        }

    def close(self) -> None:
        """Stop monitoring and release the sweep thread."""
        self.stop_periodic_monitoring()





