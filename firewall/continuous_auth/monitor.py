"""v2.2 Continuous Authorization Monitor.

Monitors security state changes and triggers continuous revalidation.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from firewall.sdk import FirewallSDK

from firewall.continuous_auth.engine import (
    ContinuousAuthorizationEngine,
    RevalidationResult,
    RevalidationTrigger,
)

@dataclass(frozen=True)
class MonitoringConfig:
    """Configuration for continuous authorization monitoring."""

    # Minimum interval between revalidations for the same decision (seconds)
    min_revalidation_interval: float = 1.0

    # Maximum age of a cached decision before forced revalidation (seconds)
    max_decision_age: float = 300.0

    # Triggers that should cause immediate revalidation
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

    # Whether to auto-revalidate on periodic timer
    enable_periodic_revalidation: bool = True
    periodic_interval: float = 60.0


@dataclass(frozen=True)
class MonitoredDecision:
    """A decision being monitored for continuous revalidation."""

    capability_fingerprint: str
    action: str
    request: dict[str, Any]
    request_hash: str
    cache_key: str
    last_revalidated: float
    revalidation_count: int = 0
    last_result: Optional[RevalidationResult] = None


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
    ) -> None:
        if not isinstance(engine, ContinuousAuthorizationEngine):
            raise TypeError("engine must be a ContinuousAuthorizationEngine")

        # To avoid circular imports, we avoid using isinstance(sdk, FirewallSDK)
        # here if FirewallSDK is not imported. We trust the type hint.

        self._engine = engine
        self._sdk = sdk
        self._config = config or MonitoringConfig()
        self._clock = clock or time.time
        self._on_revalidation = on_revalidation
        self._lock = threading.RLock()

        self._monitored: dict[str, MonitoredDecision] = {}
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

    def monitor_decision(
        self,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
        request_hash: str,
        cache_key: str,
    ) -> None:
        """Register a decision for continuous monitoring."""
        with self._lock:
            self._monitored[cache_key] = MonitoredDecision(
                capability_fingerprint=capability_fingerprint,
                action=action,
                request=request,
                request_hash=request_hash,
                cache_key=cache_key,
                last_revalidated=float(self._clock()),
            )

    def unmonitor_decision(self, cache_key: str) -> None:
        """Stop monitoring a decision."""
        with self._lock:
            self._monitored.pop(cache_key, None)

    def check_and_revalidate(
        self,
        capability_fingerprint: str,
        action: str,
        request: dict,
        cache_key: str,
        trigger: RevalidationTrigger,
    ) -> Optional[RevalidationResult]:
        """
        Check if revalidation is needed and perform it if so.

        Returns the RevalidationResult if revalidation occurred, None otherwise.
        """
        with self._lock:
            monitored = self._monitored.get(cache_key)
            if monitored is None:
                return None

            now = float(self._clock())
            # Check minimum interval
            if now - monitored.last_revalidated < self._config.min_revalidation_interval:
                # Unless it's an immediate trigger
                if trigger not in self._config.immediate_triggers:
                    return None

            # Check maximum age
            if now - monitored.last_revalidated > self._config.max_decision_age:
                trigger = RevalidationTrigger.TIME

        # Need to get the capability and request from somewhere
        # For now, this is a stub - the actual implementation would need
        # to retrieve the capability from the SDK registry
        try:
            # This is a simplified check - in practice we'd need to look up
            # the capability from the SDK's registry
            capability = self._lookup_capability(capability_fingerprint)
            if capability is None:
                return None

            result = self._engine.revalidate(
                capability,
                action,
                request,
                trigger=trigger,
            )

            with self._lock:
                if cache_key in self._monitored:
                    self._monitored[cache_key] = MonitoredDecision(
                        capability_fingerprint=capability_fingerprint,
                        action=action,
                        request=request,
                        request_hash=monitored.request_hash,
                        cache_key=cache_key,
                        last_revalidated=now,
                        revalidation_count=monitored.revalidation_count + 1,
                        last_result=result,
                    )

            if self._on_revalidation is not None:
                try:
                    self._on_revalidation(result)
                except Exception:
                    pass

            return result

        except Exception:
            return None

    def _lookup_capability(self, fingerprint: str):
        """Look up a capability by fingerprint from the SDK registry."""
        registry = getattr(self._sdk, "_capability_registry", {})
        return registry.get(fingerprint)

    def start_periodic_monitoring(self) -> None:
        """Start the periodic monitoring thread."""
        if not self._config.enable_periodic_revalidation:
            return

        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_periodic_monitoring(self) -> None:
        """Stop the periodic monitoring thread."""
        self._running = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None

    def _monitor_loop(self) -> None:
        """Periodic monitoring loop."""
        while self._running:
            time.sleep(self._config.periodic_interval)
            if not self._running:
                break

            with self._lock:
                cache_keys = list(self._monitored.keys())

            for cache_key in cache_keys:
                monitored = self._monitored.get(cache_key)
                if monitored is None:
                    continue

                self.check_and_revalidate(
                    capability_fingerprint=monitored.capability_fingerprint,
                    action=monitored.action,
                    request=monitored.request,
                    cache_key=cache_key,
                    trigger=RevalidationTrigger.TIME,
                )

    def get_monitored_decisions(self) -> dict[str, MonitoredDecision]:
        """Get all currently monitored decisions."""
        with self._lock:
            return dict(self._monitored)

    def get_revalidation_stats(self) -> dict[str, Any]:
        """Get statistics about revalidations."""
        with self._lock:
            total_revalidations = sum(m.revalidation_count for m in self._monitored.values())
            decisions_changed = sum(
                1 for m in self._monitored.values()
                if m.last_result is not None and m.last_result.state_changed
            )
            decisions_denied = sum(
                1 for m in self._monitored.values()
                if m.last_result is not None
                and m.last_result.original_allowed
                and not m.last_result.revalidated_allowed
            )

            return {
                "monitored_decisions": len(self._monitored),
                "total_revalidations": total_revalidations,
                "decisions_with_state_change": decisions_changed,
                "decisions_changed_allow_to_deny": decisions_denied,
            }
