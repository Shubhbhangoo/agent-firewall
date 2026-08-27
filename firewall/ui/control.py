"""Authenticated write surface for the console (control plane).

This module lets a developer connect agents and author rules from the
browser. It is the console's **only** write path, and it is deliberately
narrow.

What it does *not* do: implement, replace, or relax any authorization
logic. Every mutation below is a call to an existing public
``FirewallSDK`` method -- ``issue``, ``delegate``, ``attenuate``,
``revoke``, ``trust_issuer``, ``revoke_issuer`` -- with the same
arguments a Python caller would pass. Authorization checks are unchanged;
``check()`` runs the real ``authorize_north_star()`` and reports the
result verbatim.

Honest about the risk: a browser that can issue and delegate can **mint
authority**. That is what the user asked for, so the surface is gated
three ways:

1. It exists only when the server is started with control explicitly
   enabled -- otherwise the routes 404.
2. Every request needs a bearer token generated at startup.
3. Every attempt, successful or not, is recorded in an append-only audit
   list that the UI displays, so UI-originated authority is never
   invisible.

Input validation here mirrors the SDK's own rules (for example the
positive-integer requirement on ``max_delegation_depth``); it never
substitutes for them.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.simulation import (
    CaseRecorder,
    Rollout,
    RolloutError,
    RuleSet,
    SimulationError,
    simulate,
)
from firewall.ui import introspect


#: Ceiling on user-supplied constraint maps, so a browser cannot post an
#: unbounded object into a signed capability.
MAX_CONSTRAINT_KEYS = 32

#: Ceiling on any single user-supplied string.
MAX_STRING = 200

#: Default capability lifetime when the caller does not specify one.
DEFAULT_TTL_SECONDS = 3600

#: Ceiling on a requested lifetime (~30 days).
MAX_TTL_SECONDS = 30 * 24 * 3600

#: Retained audit entries.
AUDIT_LIMIT = 500


class ControlError(Exception):
    """Raised for an invalid or rejected control-plane request."""


# ======================================================================
# Input validation
# ======================================================================


def _need_str(
    value: Any,
    field: str,
    *,
    max_length: int = MAX_STRING,
) -> str:
    if not isinstance(value, str):
        raise ControlError(
            f"{field} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ControlError(
            f"{field} must not be empty"
        )

    if len(cleaned) > max_length:
        raise ControlError(
            f"{field} must be at most "
            f"{max_length} characters"
        )

    return cleaned


def _optional_str(
    value: Any,
    field: str,
) -> Optional[str]:
    if value is None or value == "":
        return None

    return _need_str(value, field)


def _need_constraints(
    value: Any,
) -> Optional[dict[str, Any]]:
    """Validate a user-authored constraint map.

    Shape only. What a constraint *means* is decided by the existing
    constraint and policy engine, which this module does not touch.
    """

    if value is None or value == "":
        return None

    if not isinstance(value, dict):
        raise ControlError(
            "constraints must be a JSON object"
        )

    if len(value) > MAX_CONSTRAINT_KEYS:
        raise ControlError(
            "constraints may hold at most "
            f"{MAX_CONSTRAINT_KEYS} keys"
        )

    cleaned: dict[str, Any] = {}

    for key, item in value.items():
        name = _need_str(key, "constraint name")

        if isinstance(item, bool) or item is None:
            cleaned[name] = item
        elif isinstance(item, (int, float)):
            if not isinstance(
                item, bool
            ) and not _finite(item):
                raise ControlError(
                    f"constraint {name} must be finite"
                )
            cleaned[name] = item
        elif isinstance(item, str):
            cleaned[name] = _need_str(
                item,
                f"constraint {name}",
            )
        elif isinstance(item, list):
            if len(item) > MAX_CONSTRAINT_KEYS:
                raise ControlError(
                    f"constraint {name} list is too long"
                )
            cleaned[name] = [
                _scalar(entry, name)
                for entry in item
            ]
        else:
            raise ControlError(
                f"constraint {name} has an "
                "unsupported value type"
            )

    return cleaned


def _finite(value: Any) -> bool:
    return (
        value == value
        and value not in (float("inf"), float("-inf"))
    )


def _scalar(value: Any, name: str) -> Any:
    if isinstance(value, bool) or value is None:
        return value

    if isinstance(value, (int, float)):
        if not _finite(value):
            raise ControlError(
                f"constraint {name} must be finite"
            )
        return value

    if isinstance(value, str):
        return _need_str(
            value,
            f"constraint {name}",
        )

    raise ControlError(
        f"constraint {name} has an "
        "unsupported value type"
    )


def _need_ttl(value: Any) -> float:
    if value is None or value == "":
        return DEFAULT_TTL_SECONDS

    if isinstance(value, bool) or not isinstance(
        value,
        (int, float),
    ):
        raise ControlError(
            "expires_in must be a number of seconds"
        )

    if not _finite(value) or value <= 0:
        raise ControlError(
            "expires_in must be positive"
        )

    if value > MAX_TTL_SECONDS:
        raise ControlError(
            "expires_in must be at most "
            f"{MAX_TTL_SECONDS} seconds"
        )

    return float(value)


def _need_depth(value: Any) -> Optional[int]:
    """Mirror the SDK's own ``max_delegation_depth`` contract."""

    if value is None or value == "":
        return None

    if isinstance(value, bool) or not isinstance(
        value,
        int,
    ):
        raise ControlError(
            "max_delegation_depth must be an integer"
        )

    if value <= 0:
        raise ControlError(
            "max_delegation_depth must be positive"
        )

    return value


# ======================================================================
# Control plane
# ======================================================================


class ControlPlane:
    """Narrow, audited write surface over one live ``FirewallSDK``."""

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        signing_key_id: str = "console-control-key",
    ):
        if not isinstance(sdk, FirewallSDK):
            raise TypeError(
                "sdk must be a FirewallSDK"
            )

        self.sdk = sdk
        self._audit: list[dict[str, Any]] = []
        self._seq = 0

        # Capabilities this control plane has minted or observed, so the
        # UI can address them by fingerprint.
        self._known: dict[str, Capability] = {}

        # Real requests the console has evaluated, kept so a proposed
        # rule change can be replayed against traffic that actually
        # happened instead of against a guess. Recording happens after a
        # decision is returned, so it cannot influence one.
        self._recorder = CaseRecorder()

        # The most recent staged rule change, retained so it can be
        # rolled back to an exact restore point.
        self._rollout: Optional[Rollout] = None

        # A signing key is required to issue at all. Reuse the SDK's
        # active key when it already has one; ``active_key()`` raises
        # rather than returning None when there is none.
        try:
            has_key = sdk.active_key() is not None
        except RuntimeError:
            has_key = False

        if not has_key:
            sdk.generate_key(signing_key_id)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _record(
        self,
        action: str,
        *,
        ok: bool,
        target: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        self._seq += 1

        self._audit.append(
            {
                "seq": self._seq,
                "timestamp": time.time(),
                "action": action,
                "ok": ok,
                "target": target,
                "detail": detail or {},
                "error": error,
            }
        )

        if len(self._audit) > AUDIT_LIMIT:
            del self._audit[
                : len(self._audit) - AUDIT_LIMIT
            ]

    def audit(self) -> list[dict[str, Any]]:
        """Newest first."""

        return list(reversed(self._audit))

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def _register(
        self,
        capability: Capability,
    ) -> str:
        fingerprint = self.sdk.fingerprint(
            capability
        )
        self._known[fingerprint] = capability
        return fingerprint

    def _lookup(
        self,
        fingerprint: Any,
    ) -> Capability:
        wanted = _need_str(
            fingerprint,
            "fingerprint",
        )

        if wanted in self._known:
            return self._known[wanted]

        matches = [
            value
            for key, value in self._known.items()
            if key.startswith(wanted)
        ]

        if len(matches) == 1:
            return matches[0]

        if not matches:
            raise ControlError(
                "unknown capability fingerprint"
            )

        raise ControlError(
            "ambiguous capability fingerprint"
        )

    def _view(
        self,
        capability: Capability,
    ) -> dict[str, Any]:
        return introspect.capability_view(
            self.sdk,
            capability,
        )

    def inventory(self) -> list[dict[str, Any]]:
        return [
            self._view(capability)
            for capability in self._known.values()
        ]

    def agents(self) -> list[dict[str, Any]]:
        """Connected agents, with their capabilities."""

        grouped: dict[str, list[dict[str, Any]]] = {}

        for capability in self._known.values():
            grouped.setdefault(
                capability.agent_id,
                [],
            ).append(self._view(capability))

        return [
            {
                "agent": agent,
                "capabilities": views,
                "live": any(
                    not view["effectively_revoked"]
                    for view in views
                ),
            }
            for agent, views in sorted(
                grouped.items()
            )
        ]

    def rules(self) -> dict[str, Any]:
        """Currently configured, globally scoped rules."""

        return {
            "max_delegation_depth": (
                self.sdk.max_delegation_depth
            ),
            "trusted_issuers": sorted(
                {
                    capability.issuer
                    for capability in self._known.values()
                    if self.sdk.is_issuer_trusted(
                        capability.issuer
                    )
                }
            ),
        }

    def state(self) -> dict[str, Any]:
        return {
            "agents": self.agents(),
            "rules": self.rules(),
            "audit": self.audit(),
            "simulation": self.simulation(),
            "posture": introspect.posture_view(
                self.sdk,
                agents=tuple(
                    entry["agent"]
                    for entry in self.agents()
                ),
            ),
            "lifecycle": introspect.lifecycle_view(
                self.sdk,
                limit=40,
            ),
        }

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def connect_agent(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Issue a first capability for a new agent.

        This is ``FirewallSDK.issue()`` -- nothing more. The wording
        "connect" is about the workflow, not a new mechanism.
        """

        try:
            agent = _need_str(
                payload.get("agent"),
                "agent",
            )
            capability_name = _need_str(
                payload.get("capability"),
                "capability",
            )
            issuer = (
                _optional_str(
                    payload.get("issuer"),
                    "issuer",
                )
                or "trusted-issuer"
            )
            constraints = _need_constraints(
                payload.get("constraints")
            )
            tool = _optional_str(
                payload.get("tool"),
                "tool",
            )
            ttl = _need_ttl(
                payload.get("expires_in")
            )
        except ControlError as exc:
            self._record(
                "connect_agent",
                ok=False,
                error=str(exc),
            )
            raise

        try:
            if not self.sdk.is_issuer_trusted(
                issuer
            ):
                self.sdk.trust_issuer(issuer)
                self._record(
                    "trust_issuer",
                    ok=True,
                    target=issuer,
                    detail={
                        "implied_by": "connect_agent"
                    },
                )

            capability = self.sdk.issue(
                agent=agent,
                capability=capability_name,
                issuer=issuer,
                constraints=constraints,
                tool=tool,
                expires_at=time.time() + ttl,
            )
        except Exception as exc:
            self._record(
                "connect_agent",
                ok=False,
                target=agent,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise ControlError(
                f"issue failed: {exc}"
            ) from exc

        fingerprint = self._register(capability)

        self._record(
            "connect_agent",
            ok=True,
            target=agent,
            detail={
                "fingerprint": introspect.short_fingerprint(
                    fingerprint
                ),
                "capability": capability_name,
                "constraints": constraints,
                "tool": tool,
            },
        )

        return self._view(capability)

    def delegate(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            parent = self._lookup(
                payload.get("fingerprint")
            )
            delegatee = _need_str(
                payload.get("delegatee"),
                "delegatee",
            )
            constraints = _need_constraints(
                payload.get("constraints")
            )
        except ControlError as exc:
            self._record(
                "delegate",
                ok=False,
                error=str(exc),
            )
            raise

        try:
            child = self.sdk.delegate(
                parent,
                self.sdk.active_key().private_key,
                delegatee=delegatee,
                constraints=constraints,
            ).child
        except Exception as exc:
            self._record(
                "delegate",
                ok=False,
                target=delegatee,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise ControlError(
                f"delegate failed: {exc}"
            ) from exc

        fingerprint = self._register(child)

        self._record(
            "delegate",
            ok=True,
            target=delegatee,
            detail={
                "parent": introspect.short_fingerprint(
                    self.sdk.fingerprint(parent)
                ),
                "fingerprint": introspect.short_fingerprint(
                    fingerprint
                ),
                "constraints": constraints,
            },
        )

        return self._view(child)

    def attenuate(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            parent = self._lookup(
                payload.get("fingerprint")
            )
            constraints = _need_constraints(
                payload.get("constraints")
            )

            if constraints is None:
                raise ControlError(
                    "attenuation requires constraints"
                )
        except ControlError as exc:
            self._record(
                "attenuate",
                ok=False,
                error=str(exc),
            )
            raise

        try:
            narrowed = self.sdk.attenuate(
                parent,
                self.sdk.active_key().private_key,
                constraints=constraints,
            )
        except Exception as exc:
            self._record(
                "attenuate",
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise ControlError(
                f"attenuate failed: {exc}"
            ) from exc

        fingerprint = self._register(narrowed)

        self._record(
            "attenuate",
            ok=True,
            target=narrowed.agent_id,
            detail={
                "fingerprint": introspect.short_fingerprint(
                    fingerprint
                ),
                "constraints": constraints,
            },
        )

        return self._view(narrowed)

    def revoke(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            capability = self._lookup(
                payload.get("fingerprint")
            )
            reason = (
                _optional_str(
                    payload.get("reason"),
                    "reason",
                )
                or "revoked from console"
            )
        except ControlError as exc:
            self._record(
                "revoke",
                ok=False,
                error=str(exc),
            )
            raise

        self.sdk.revoke(
            capability,
            reason=reason,
        )

        self._record(
            "revoke",
            ok=True,
            target=capability.agent_id,
            detail={
                "fingerprint": introspect.short_fingerprint(
                    self.sdk.fingerprint(capability)
                ),
                "reason": reason,
            },
        )

        return self._view(capability)

    def set_issuer_trust(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            issuer = _need_str(
                payload.get("issuer"),
                "issuer",
            )
            trusted = payload.get("trusted")

            if not isinstance(trusted, bool):
                raise ControlError(
                    "trusted must be a boolean"
                )
        except ControlError as exc:
            self._record(
                "set_issuer_trust",
                ok=False,
                error=str(exc),
            )
            raise

        if trusted:
            self.sdk.trust_issuer(issuer)
        else:
            self.sdk.revoke_issuer(issuer)

        self._record(
            "set_issuer_trust",
            ok=True,
            target=issuer,
            detail={"trusted": trusted},
        )

        return {
            "issuer": issuer,
            "trusted": self.sdk.is_issuer_trusted(
                issuer
            ),
        }

    def set_depth_policy(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Set the delegation depth ceiling.

        Validation mirrors the SDK constructor's own contract: a positive
        integer, or ``None`` for unbounded.
        """

        try:
            depth = _need_depth(
                payload.get("max_delegation_depth")
            )
        except ControlError as exc:
            self._record(
                "set_depth_policy",
                ok=False,
                error=str(exc),
            )
            raise

        self.sdk.max_delegation_depth = depth

        self._record(
            "set_depth_policy",
            ok=True,
            detail={"max_delegation_depth": depth},
        )

        return self.rules()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def check(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a real authorization against a connected capability.

        This is the authoritative pipeline, with real side effects. The
        result is reported verbatim.
        """

        try:
            capability = self._lookup(
                payload.get("fingerprint")
            )
            action = _need_str(
                payload.get("action"),
                "action",
            )
            request = payload.get("request")

            if request is None:
                request = {}

            if not isinstance(request, dict):
                raise ControlError(
                    "request must be a JSON object"
                )
        except ControlError as exc:
            self._record(
                "check",
                ok=False,
                error=str(exc),
            )
            raise

        decision = self.sdk.authorize_north_star(
            capability,
            action,
            request,
        )

        view = introspect.decision_view(decision)

        # Recorded only after the verdict exists, so the recorder can
        # never be part of the decision. A failure to record is not
        # allowed to turn a real decision into an error.
        try:
            self._recorder.record(
                self.sdk,
                capability,
                action,
                request,
                decision,
                note="authored in console",
            )
        except Exception:
            pass

        self._record(
            "check",
            ok=True,
            target=capability.agent_id,
            detail={
                "action": action,
                "allowed": view["allowed"],
                "reason": view["reason"],
            },
        )

        return {
            "decision": view,
            "attributed_phase": introspect.attribute_reason(
                decision.reason
            ),
            "phases": introspect.phase_trace(
                self.sdk,
                allowed=decision.allowed,
                reason=decision.reason,
            ),
            "authority": introspect.authority_view(
                self.sdk,
                capability,
            ),
            "request": {
                "action": action,
                "payload": dict(request),
            },
        }

    # ------------------------------------------------------------------
    # Rule simulation and staged rollout (v1.7)
    # ------------------------------------------------------------------

    def _candidate(
        self,
        payload: dict[str, Any],
    ) -> RuleSet:
        """Read a proposed rule set out of a browser payload.

        Anything the payload omits is inherited from the rules currently
        in force. That matters: a partial payload must never be read as
        "untrust every issuer", which is how a depth-only change could
        otherwise look like a total lockout.
        """

        current = RuleSet.from_sdk(self.sdk)
        changes: dict[str, Any] = {}

        if "max_delegation_depth" in payload:
            changes["max_delegation_depth"] = (
                _need_depth(
                    payload.get(
                        "max_delegation_depth"
                    )
                )
            )

        if "trusted_issuers" in payload:
            issuers = payload.get(
                "trusted_issuers"
            )

            if not isinstance(issuers, list):
                raise ControlError(
                    "trusted_issuers must be a list"
                )

            changes["trusted_issuers"] = [
                _need_str(issuer, "issuer")
                for issuer in issuers
            ]

        try:
            return current.replace(**changes)
        except SimulationError as exc:
            raise ControlError(str(exc)) from exc

    def cases(self) -> list[dict[str, Any]]:
        """Requests recorded from this console, for replay."""

        return [
            case.to_dict()
            for case in self._recorder.cases()
        ]

    def simulation(self) -> dict[str, Any]:
        """Projection of what is available to simulate against."""

        return {
            "recorded_cases": len(self._recorder),
            "rollout": (
                self._rollout.state()
                if self._rollout is not None
                else None
            ),
        }

    def simulate(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Report what a proposed rule change would do.

        Read-only with respect to the live SDK: the candidate rules are
        only ever applied inside throwaway replay workspaces.
        """

        if not isinstance(payload, dict):
            raise ControlError(
                "payload must be a JSON object"
            )

        try:
            candidate = self._candidate(payload)
            current = RuleSet.from_sdk(self.sdk)
            report = simulate(
                self._recorder.cases(),
                current,
                candidate,
            )
        except (
            ControlError,
            SimulationError,
        ) as exc:
            self._record(
                "simulate",
                ok=False,
                error=str(exc),
            )
            raise ControlError(
                str(exc)
            ) from exc

        self._record(
            "simulate",
            ok=True,
            detail={
                "candidate": candidate.to_dict(),
                "summary": report.summary(),
                "newly_denied": report.blast_radius[
                    "newly_denied"
                ],
                "safe": report.safe,
            },
        )

        return {
            "report": report.to_dict(),
            "candidate": candidate.to_dict(),
            "current": current.to_dict(),
        }

    def promote(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Simulate a rule change, then enforce it if permitted.

        The simulation is not optional and not caller-supplied: it is run
        here, immediately before promotion, against the rules actually in
        force. A change that newly denies recorded traffic is refused
        unless the payload acknowledges it, and the acknowledgement is
        written into the rollout history.
        """

        if not isinstance(payload, dict):
            raise ControlError(
                "payload must be a JSON object"
            )

        acknowledge = payload.get(
            "acknowledge",
            False,
        )

        if not isinstance(acknowledge, bool):
            raise ControlError(
                "acknowledge must be a boolean"
            )

        label = _optional_str(
            payload.get("label"),
            "label",
        )

        try:
            candidate = self._candidate(payload)
            rollout = Rollout(
                self.sdk,
                candidate,
                label=label or "console rule change",
            )
            report = rollout.simulate(
                self._recorder.cases()
            )
            restore_point = rollout.promote(
                acknowledge=acknowledge,
            )
        except (
            ControlError,
            SimulationError,
            RolloutError,
        ) as exc:
            self._record(
                "promote",
                ok=False,
                error=str(exc),
            )
            raise ControlError(
                str(exc)
            ) from exc

        self._rollout = rollout

        self._record(
            "promote",
            ok=True,
            detail={
                "enforced": candidate.to_dict(),
                "restore_point": (
                    restore_point.to_dict()
                ),
                "acknowledged": acknowledge,
                "summary": report.summary(),
            },
        )

        return {
            "rollout": rollout.state(),
            "rules": self.rules(),
        }

    def rollback(
        self,
        payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Restore the rules displaced by the last promotion."""

        if self._rollout is None:
            self._record(
                "rollback",
                ok=False,
                error="nothing has been promoted",
            )
            raise ControlError(
                "nothing has been promoted"
            )

        try:
            restored = self._rollout.rollback()
        except RolloutError as exc:
            self._record(
                "rollback",
                ok=False,
                error=str(exc),
            )
            raise ControlError(
                str(exc)
            ) from exc

        self._record(
            "rollback",
            ok=True,
            detail={
                "restored": restored.to_dict()
            },
        )

        return {
            "rollout": self._rollout.state(),
            "rules": self.rules(),
        }
