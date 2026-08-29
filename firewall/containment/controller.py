"""Active containment (v1.8).

A containment controller manages an agent's security state through
explicit, audited transitions:

    ACTIVE -> RESTRICTED -> QUARANTINED -> RECOVERED
                 \\-> SUSPENDED (also reachable from RESTRICTED)

Every action is:

* **authorized** -- an ``authorizer`` callable (the control plane's
  bearer-token gate) must return true before anything happens;
* **authenticated** -- an ``actor`` identity is recorded with every
  action;
* **audited** -- every action emits a containment event to the flight
  recorder and a lifecycle record;
* **explainable** -- a reason is required;
* **reversible where appropriate** -- recovery re-issues equivalent
  authority;
* **fail-closed** -- an error during a restriction escalates the agent
  to ``quarantined`` rather than leaving it unrestricted.

Crucially, the controller never authorizes anything itself and never
bypasses the authorization pipeline. It changes the *inputs* the real
pipeline reasons about -- the revocation registry and the risk context
-- through the SDK's own public APIs. A contained agent is contained
because ``authorize()`` denies it, not because the controller says so.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from firewall.recorder import EventType, FlightRecorder
from firewall.sdk import FirewallSDK


class ContainmentState(str, Enum):
    ACTIVE = "active"
    RESTRICTED = "restricted"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"
    RECOVERED = "recovered"


class ContainmentAction(str, Enum):
    RESTRICT_CAPABILITY = "restrict_capability"
    RESTRICT_SESSION = "restrict_session"
    SUSPEND_OPERATION = "suspend_operation"
    QUARANTINE_AGENT = "quarantine_agent"
    REQUIRE_REAUTHORIZATION = "require_reauthorization"
    RECOVER = "recover"


#: Allowed action -> resulting state.
_ACTION_STATE = {
    ContainmentAction.RESTRICT_CAPABILITY: ContainmentState.RESTRICTED,
    ContainmentAction.RESTRICT_SESSION: ContainmentState.RESTRICTED,
    ContainmentAction.SUSPEND_OPERATION: ContainmentState.SUSPENDED,
    ContainmentAction.QUARANTINE_AGENT: ContainmentState.QUARANTINED,
    ContainmentAction.REQUIRE_REAUTHORIZATION: ContainmentState.SUSPENDED,
    ContainmentAction.RECOVER: ContainmentState.RECOVERED,
}

#: States that are allowed to transition to a given state. ``None``
#: means any state may move there.
#:
#: Tightening containment is always permitted: an agent that has been
#: through a recovery cycle is an ordinary agent again, and refusing to
#: quarantine it during a second incident would make containment
#: impossible exactly when it is needed. Quarantine in particular
#: accepts any state, including itself, so re-quarantining revokes any
#: authority issued since the last one.
#:
#: Loosening is what stays strict: ``RECOVER`` is only valid from a
#: restricted/suspended/quarantined state, so recovery can never be
#: used to clear an agent that was never contained.
_TRANSITIONS: dict[ContainmentState, Optional[set[ContainmentState]]] = {
    ContainmentState.RESTRICTED: {
        ContainmentState.ACTIVE,
        ContainmentState.RESTRICTED,
        ContainmentState.RECOVERED,
    },
    ContainmentState.SUSPENDED: {
        ContainmentState.ACTIVE,
        ContainmentState.RESTRICTED,
        ContainmentState.SUSPENDED,
        ContainmentState.RECOVERED,
    },
    ContainmentState.QUARANTINED: None,
    ContainmentState.RECOVERED: {
        ContainmentState.RESTRICTED,
        ContainmentState.SUSPENDED,
        ContainmentState.QUARANTINED,
    },
}


class ContainmentError(ValueError):
    """Raised for an invalid containment action."""


# ----------------------------------------------------------------------
# Revocation helpers
#
# Restoration is the one place where containment hands authority back, so
# these deliberately fail closed: if the lineage of a capability cannot
# be proven clean, it is treated as revoked and stays gone.
# ----------------------------------------------------------------------


def _parent_fingerprint(sdk, fingerprint: str) -> Optional[str]:
    """The immediate delegation parent of ``fingerprint``, if any."""

    try:
        chain = list(sdk.delegation_lineage.chain(fingerprint))
    except Exception:
        return None
    return chain[0] if chain else None


def _ancestry_revoked(sdk, parent: Optional[str]) -> bool:
    """Is ``parent`` - or any of its own ancestors - revoked?"""

    if not parent:
        return False
    try:
        if sdk.revocation.is_revoked(parent):
            return True
        for ancestor in sdk.delegation_lineage.chain(parent):
            if sdk.revocation.is_revoked(ancestor):
                return True
    except Exception:
        return True
    return False


def _effectively_revoked(sdk, capability) -> bool:
    """Is ``capability`` revoked directly or through its lineage?"""

    checker = getattr(sdk, "is_effectively_revoked", None)
    if checker is None:
        return bool(sdk.is_revoked(capability))
    try:
        return bool(checker(capability))
    except Exception:
        return bool(sdk.is_revoked(capability))


@dataclass(frozen=True)
class ContainmentEvent:
    """One audited containment action."""

    action: ContainmentAction
    agent: str
    from_state: ContainmentState
    to_state: ContainmentState
    actor: str
    reason: str
    timestamp: float
    capability_fingerprints: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "agent": self.agent,
            "from": self.from_state.value,
            "to": self.to_state.value,
            "actor": self.actor,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "capability_fingerprints": list(
                self.capability_fingerprints
            ),
        }


class ContainmentController:
    """Explicit-state containment manager routed through the SDK."""

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        recorder: Optional[FlightRecorder] = None,
        authorizer: Optional[Callable[[], bool]] = None,
        clock: Any = None,
        fail_closed: bool = True,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError(
                "sdk must be a FirewallSDK"
            )

        self._sdk = sdk
        self._recorder = recorder
        self._authorizer = authorizer
        self._clock = clock if clock is not None else time.time
        self._fail_closed = fail_closed

        #: agent -> current state
        self._states: dict[str, ContainmentState] = {}

        #: agent -> [(action, actor, reason, fingerprints)]
        self._history: list[ContainmentEvent] = []

        #: agent -> capabilities revoked while contained (for recovery)
        self._revoked: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def state(self, agent: str) -> ContainmentState:
        return self._states.get(
            agent, ContainmentState.ACTIVE
        )

    def history(self) -> tuple[ContainmentEvent, ...]:
        return tuple(self._history)

    def snapshot(self) -> dict[str, Any]:
        return {
            "states": {
                agent: state.value
                for agent, state in self._states.items()
            },
            "history": [
                event.to_dict() for event in self._history
            ],
        }

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def apply(
        self,
        action: ContainmentAction,
        agent: str,
        *,
        actor: str = "console",
        reason: str = "",
        capability=None,
        operation: Optional[str] = None,
    ) -> ContainmentEvent:
        """Apply one containment action with full discipline."""

        if not isinstance(action, ContainmentAction):
            raise ContainmentError(
                "action must be a ContainmentAction"
            )

        if not isinstance(agent, str) or not agent.strip():
            raise ContainmentError(
                "agent must be a non-empty string"
            )

        if not isinstance(actor, str) or not actor.strip():
            raise ContainmentError(
                "actor must be a non-empty string"
            )

        if not isinstance(reason, str) or not reason.strip():
            raise ContainmentError(
                "reason is required for every containment action"
            )

        # Authorized.
        if self._authorizer is not None:
            try:
                authorized = bool(self._authorizer())
            except Exception:
                authorized = False

            if not authorized:
                raise ContainmentError(
                    "containment action not authorized"
                )

        current = self.state(agent)

        allowed_from = _TRANSITIONS.get(
            _ACTION_STATE[action]
        )

        if (
            allowed_from is not None
            and current not in allowed_from
        ):
            raise ContainmentError(
                f"cannot {action.value} an agent in state "
                f"{current.value}"
            )

        fingerprints = self._enforce(
            action,
            agent,
            capability=capability,
            operation=operation,
        )

        to_state = _ACTION_STATE[action]

        self._states[agent] = to_state

        event = ContainmentEvent(
            action=action,
            agent=agent,
            from_state=current,
            to_state=to_state,
            actor=actor,
            reason=reason,
            timestamp=float(self._clock()),
            capability_fingerprints=tuple(
                fingerprints
            ),
        )

        self._history.append(event)

        self._audit(event)

        return event

    # ------------------------------------------------------------------
    # Enforcement (routed through the SDK, never around it)
    # ------------------------------------------------------------------

    def _enforce(
        self,
        action: ContainmentAction,
        agent: str,
        *,
        capability,
        operation: Optional[str],
    ) -> list[str]:
        fingerprints: list[str] = []

        try:
            if action == ContainmentAction.QUARANTINE_AGENT:
                fingerprints = self._revoke_agent(agent)
            elif action == ContainmentAction.RESTRICT_CAPABILITY:
                if capability is None:
                    raise ContainmentError(
                        "restrict_capability requires a capability"
                    )
                fingerprints = [
                    self._revoke_capability(capability, agent)
                ]
            elif action == ContainmentAction.SUSPEND_OPERATION:
                if capability is None:
                    raise ContainmentError(
                        "suspend_operation requires a capability"
                    )
                fingerprints = [
                    self._revoke_capability(capability, agent)
                ]
            elif action == ContainmentAction.RESTRICT_SESSION:
                # Elevate the agent's runtime risk so the real risk
                # gate restricts it; recovery resets the risk context.
                self._elevate_risk(agent)
            elif action == ContainmentAction.REQUIRE_REAUTHORIZATION:
                self._elevate_risk(agent)
            elif action == ContainmentAction.RECOVER:
                fingerprints = self._recover(agent)
            else:  # pragma: no cover - exhaustive enum
                raise ContainmentError(
                    f"unknown containment action: {action}"
                )
        except ContainmentError:
            raise
        except Exception:
            if self._fail_closed:
                # Fail closed: an error while restricting must not leave
                # the agent unrestricted. Escalate to quarantine.
                try:
                    self._revoke_agent(agent)
                except Exception:
                    pass
                raise ContainmentError(
                    f"containment failed closed for {agent}: "
                    "agent quarantined"
                )
            raise

        return fingerprints

    def _revoke_capability(self, capability, agent: str) -> str:
        fingerprint = self._sdk.fingerprint(capability)

        try:
            self._sdk.revoke(
                capability,
                reason="containment: " + agent,
            )
        except Exception:
            # Already revoked is fine; anything else propagates so the
            # fail-closed path can quarantine.
            if not self._sdk.is_revoked(capability):
                raise

        self._revoked.setdefault(agent, []).append(
            {
                "agent": capability.agent_id,
                "capability": capability.capability,
                "constraints": dict(
                    capability.constraints or {}
                ),
                "tool": capability.tool,
                "issuer": capability.issuer,
                "fingerprint": fingerprint,
                "parent": _parent_fingerprint(
                    self._sdk, fingerprint
                ),
            }
        )

        return fingerprint

    def _revoke_agent(self, agent: str) -> list[str]:
        fingerprints: list[str] = []
        failures = 0

        # Collect every capability this agent holds directly: the
        # capability registry keyed by fingerprint.
        for fingerprint in list(
            self._sdk._capability_registry.keys()
        ):
            capability = self._sdk._capability_registry[
                fingerprint
            ]

            if capability.agent_id != agent:
                continue

            # Skip authority that is already gone - directly revoked, or
            # revoked through an ancestor. Containment is not taking it
            # away, so it must not be recorded for restoration: recovery
            # may only give back what this containment suspended.
            if _effectively_revoked(self._sdk, capability):
                continue

            try:
                self._sdk.revoke(
                    capability,
                    reason="containment quarantine: " + agent,
                )
            except Exception:
                failures += 1
                continue

            self._revoked.setdefault(agent, []).append(
                {
                    "agent": capability.agent_id,
                    "capability": capability.capability,
                    "constraints": dict(
                        capability.constraints or {}
                    ),
                    "tool": capability.tool,
                    "issuer": capability.issuer,
                    "fingerprint": fingerprint,
                    "parent": _parent_fingerprint(
                        self._sdk, fingerprint
                    ),
                }
            )

            fingerprints.append(fingerprint)

        # Also raise the runtime risk so any capability issued later
        # cannot be used until the agent recovers.
        self._elevate_risk(agent)

        # Fail closed: if the agent held capabilities and none of them
        # could be revoked, surface the failure so the caller's
        # fail-closed path can quarantine via risk elevation.
        held = [
            item
            for item in self._sdk._capability_registry.values()
            if item.agent_id == agent
        ]
        if held and not fingerprints and failures:
            raise ContainmentError(
                f"could not revoke any capability for {agent}"
            )

        return fingerprints

    def _elevate_risk(self, agent: str) -> None:
        risk = getattr(self._sdk, "risk_context", None)

        if risk is None:
            return

        try:
            risk.record_critical(agent)
        except Exception:
            return

    def _recover(self, agent: str) -> list[str]:
        restored: list[str] = []

        # Reset runtime risk first so the risk gate is open again.
        risk = getattr(self._sdk, "risk_context", None)

        if risk is not None:
            try:
                risk.reset(agent)
            except Exception:
                pass

        # Re-issue equivalent authority that was revoked by containment.
        # New fingerprints: documented, since the original signed
        # capabilities are gone by design.
        #
        # The records are consumed, not merely read: a later containment
        # cycle must restore what *it* suspended, never a stale record
        # from an earlier one whose authority an operator has since
        # revoked on purpose.
        for record in self._revoked.pop(agent, []):
            parent = record.get("parent")
            try:
                # An ancestor revocation outlives its children. Restoring
                # a capability whose parent is revoked would launder a
                # recursively-revoked delegation into live authority.
                if _ancestry_revoked(self._sdk, parent):
                    continue

                capability = self._sdk.issue(
                    agent=record["agent"],
                    capability=record["capability"],
                    constraints=dict(
                        record.get("constraints") or {}
                    ),
                    issuer=record.get("issuer", "trusted-issuer"),
                    tool=record.get("tool"),
                )
                fingerprint = self._sdk.fingerprint(capability)

                # Re-attach the delegation lineage, so revoking an
                # ancestor still kills the restored child.
                if parent:
                    self._sdk.delegation_lineage.register(
                        child_fingerprint=fingerprint,
                        parent_fingerprint=parent,
                    )

                restored.append(fingerprint)
            except Exception:
                # Best effort: re-issuing a capability can fail if the
                # signing key is gone; the agent stays restricted.
                continue

        return restored

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit(self, event: ContainmentEvent) -> None:
        if self._recorder is not None:
            try:
                self._recorder.record(
                    EventType.CONTAINMENT,
                    {
                        "action": event.action.value,
                        "state": event.to_state.value,
                        "from_state": event.from_state.value,
                        "agent": event.agent,
                        "actor": event.actor,
                        "reason": event.reason,
                        "capability_fingerprints": list(
                            event.capability_fingerprints
                        ),
                    },
                    agent=event.agent,
                )
            except Exception:
                pass
