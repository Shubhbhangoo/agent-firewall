"""v2.1 Real-Time Agent Defense Mesh (firewall.defense).

A continuously evaluated defense layer wrapped around the v2.0 control
plane. The mesh answers four questions about every agent, on every
evaluation:

* **who** -- live identity verification against ``IdentityRegistry``;
* **trusted** -- dynamic trust evaluation (pluggable provider, default
  derives from identity issuer trust + posture);
* **can** -- continuous capability evaluation (pluggable provider,
  default routes through the real ``FirewallSDK`` authorization
  pipeline or an explicit provider);
* **state** -- explicit lifecycle: ``active`` / ``restricted`` /
  ``quarantined`` / ``recovering`` / ``re_entering``.

The mesh enforces:

* **immediate capability revocation** -- quarantining an agent revokes
  every capability it holds through the v2.0 containment controller,
  which routes through the SDK's own revocation registry;
* **automatic quarantine** for compromised agents (posture-driven);
* **recovery and re-entry states** -- recovery is a deliberate,
  audited, policy-gated transition; re-entry re-verifies identity and
  posture before an agent is allowed back to ``active``;
* **auditable state transitions** -- every transition is recorded as a
  signed attestation and in an optional flight recorder;
* **fail-closed behavior** -- unknown agents, unknown states, unverified
  identities, and any provider failure deny.

Hard boundary: the mesh never authorizes anything itself. Its
capability provider is expected to call the real SDK; the mesh only
reports what the provider says. There is no path by which an agent can
elevate its own authority through the mesh: transitions are monotone
toward containment, and ``active`` can only be re-entered through
``recovering`` + explicit re-entry with identity and posture checks.
"""

from __future__ import annotations

import json
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from firewall.attest import AttestationAuthority
from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
)
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine, PostureSignal

#: Agent lifecycle states in the defense mesh.
MESH_STATES = (
    "active",
    "restricted",
    "quarantined",
    "recovering",
    "re_entering",
    "retired",
)

#: States an agent must pass through to return to active after
#: containment. Direct ``quarantined -> active`` is impossible.
_RECOVERY_PATH = (
    "quarantined",
    "recovering",
    "re_entering",
    "active",
)


class DefenseError(ValueError):
    """Raised for an invalid defense-mesh operation."""


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(
        value, (int, float)
    ):
        raise DefenseError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise DefenseError(f"{label} must be finite")
    return result


@dataclass(frozen=True)
class MeshState:
    """One agent's state in the defense mesh.

    ``trust_score`` is a real trust score: it comes from the mesh's
    ``trust_provider``, is forced to 0.0 when identity cannot be verified
    or the provider raises, and is compared against the quarantine
    threshold. Low means bad and absent means 0.0.

    It is not :attr:`firewall.adversarial.AgentSecurityProfile.
    finding_score`, which runs the other way for absence -- it starts at
    1.0 and only drops when something is *found*, so an unchecked agent
    scores near 1.0 there and records its ignorance in ``risk_level`` and
    ``gaps`` instead. That field was called ``trust_score`` until v2.3;
    passing it to ``trust_provider`` unconverted would have kept an
    unverifiable agent out of quarantine.

    ``identity_verified`` is a plain ``bool`` here on purpose. The mesh
    quarantines on anything short of a verified identity, so it has no use
    for a third "not established" value: unverified and unverifiable get
    the same treatment.
    """

    agent: str
    state: str
    identity_verified: bool
    trust_score: float
    posture: str
    capability_ok: bool
    evaluated_at: float
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "state": self.state,
            "identity_verified": self.identity_verified,
            "trust_score": self.trust_score,
            "posture": self.posture,
            "capability_ok": self.capability_ok,
            "evaluated_at": self.evaluated_at,
            "reason": self.reason,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class MeshTransition:
    """One audited state transition."""

    agent: str
    from_state: str
    to_state: str
    actor: str
    reason: str
    timestamp: float
    attestation: Optional[dict[str, Any]] = None
    event_seq: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "from": self.from_state,
            "to": self.to_state,
            "actor": self.actor,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "attestation": (
                dict(self.attestation)
                if self.attestation
                else None
            ),
            "event_seq": self.event_seq,
        }


class DefenseMesh:
    """Continuously evaluated defense layer around agents.

    ``capability_provider`` is a callable
    ``(agent) -> (allowed: bool, reason: str)``. When omitted, the mesh
    defaults to a provider that consults a live ``FirewallSDK``:
    ``True`` only while the agent holds at least one non-revoked
    capability. ``trust_provider`` is a callable
    ``(agent) -> (score: float, reason: str)``; the default derives from
    identity status and posture.

    ``posture`` must be a :class:`PostureEngine` when provided, so the
    mesh can auto-quarantine compromised agents. ``attest`` is an
    :class:`AttestationAuthority` used to sign every transition.
    """

    def __init__(
        self,
        identities: IdentityRegistry,
        *,
        containment: Optional[ContainmentController] = None,
        posture: Optional[PostureEngine] = None,
        attest: Optional[AttestationAuthority] = None,
        capability_provider: Optional[Callable[[str], tuple[bool, str]]] = None,
        trust_provider: Optional[Callable[[str], tuple[float, str]]] = None,
        recorder=None,
        clock: Any = None,
        state_path: Optional[str | Path] = None,
        quarantine_threshold: float = 0.35,
        recovery_ttl: float = 3600.0,
    ) -> None:
        if not isinstance(identities, IdentityRegistry):
            raise DefenseError(
                "identities must be an IdentityRegistry"
            )
        if posture is not None and not isinstance(
            posture, PostureEngine
        ):
            raise DefenseError("posture must be a PostureEngine")
        if containment is not None and not isinstance(
            containment, ContainmentController
        ):
            raise DefenseError(
                "containment must be a ContainmentController"
            )
        if capability_provider is not None and not callable(
            capability_provider
        ):
            raise DefenseError(
                "capability_provider must be callable"
            )
        if trust_provider is not None and not callable(
            trust_provider
        ):
            raise DefenseError("trust_provider must be callable")

        self._identities = identities
        self._posture = posture
        self._attest = attest
        self._recorder = recorder
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()

        if containment is None:
            # A containment controller without an SDK is inert: the mesh
            # uses its explicit-state machine for quarantine/recovery
            # bookkeeping and (when an SDK-backed controller is attached)
            # real revocation. When none is attached, quarantine is a
            # mesh-level state only and the capability provider must do
            # the actual enforcement.
            containment = _InertContainment(clock=self._clock)
        self._containment = containment

        self._capability_provider = capability_provider or self._default_capability
        self._trust_provider = trust_provider or self._default_trust

        self._quarantine_threshold = _finite_number(
            quarantine_threshold, "quarantine_threshold"
        )
        self._recovery_ttl = _finite_number(recovery_ttl, "recovery_ttl")
        if self._quarantine_threshold < 0.0 or self._quarantine_threshold > 1.0:
            raise DefenseError(
                "quarantine_threshold must be within [0, 1]"
            )
        if self._recovery_ttl <= 0:
            raise DefenseError("recovery_ttl must be positive")

        # agent -> mesh state
        self._states: dict[str, str] = {}
        # agent -> recovery started at
        self._recovery_started: dict[str, float] = {}
        # agent -> transition log
        self._transitions: dict[str, list[MeshTransition]] = {}
        self._seq = 0
        # last evaluation result per agent
        self._last: dict[str, MeshState] = {}
        # agent -> authority this mesh's own quarantine suspended. Only
        # these records may ever be restored; authority that was already
        # revoked before quarantine is not the mesh's to give back.
        self._contained_authority: dict[str, tuple[dict[str, Any], ...]] = {}

        self._path = Path(state_path) if state_path else None
        if self._path is not None:
            self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = json.loads(
                self._path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise DefenseError(f"cannot load mesh state: {exc}") from exc
        with self._lock:
            states = data.get("states", {})
            for agent, state in states.items():
                if state not in MESH_STATES:
                    # Fail closed: an unrecognized persisted state must
                    # never fall through to the ``active`` default.
                    raise DefenseError(
                        f"cannot load mesh state: unknown state "
                        f"{state!r} for {agent!r}"
                    )
                self._states[agent] = state
            self._recovery_started = {
                agent: float(ts)
                for agent, ts in data.get("recovery_started", {}).items()
            }
            for entry in data.get("transitions", []):
                try:
                    transition = MeshTransition(
                        agent=entry["agent"],
                        from_state=entry["from"],
                        to_state=entry["to"],
                        actor=entry["actor"],
                        reason=entry["reason"],
                        timestamp=float(entry["timestamp"]),
                        event_seq=entry.get("event_seq"),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                self._transitions.setdefault(transition.agent, []).append(
                    transition
                )

    def _save(self) -> None:
        if self._path is None:
            return
        import os
        import tempfile

        data = {
            "states": dict(self._states),
            "recovery_started": dict(self._recovery_started),
            "transitions": [
                transition.to_dict()
                for agent in sorted(self._transitions)
                for transition in self._transitions[agent]
            ],
        }
        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".mesh-state.", suffix=".tmp", dir=dir_text
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Default providers
    # ------------------------------------------------------------------

    def _default_capability(
        self, agent: str
    ) -> tuple[bool, str]:
        """Fail-closed default: an agent may act only while it holds a
        live, non-revoked capability issued to it."""

        return False, "no capability provider attached"

    def _default_trust(
        self, agent: str
    ) -> tuple[float, str]:
        identity = self._identities.get(agent)
        if identity is None:
            return 0.0, "unknown identity"
        if identity.status != "active":
            return 0.0, f"identity {identity.status}"
        score = 0.7
        reasons = ["identity active"]
        if self._posture is not None:
            posture = self._posture.state(agent).posture
            penalties = {
                "degraded": 0.1,
                "suspicious": 0.2,
                "high_risk": 0.35,
                "compromised": 0.6,
                "contained": 0.7,
            }
            if posture in penalties:
                score -= penalties[posture]
                reasons.append(f"posture {posture}")
        return max(0.0, min(1.0, score)), "; ".join(reasons)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def attach_sdk(
        self,
        sdk,
    ) -> None:
        """Attach a live ``FirewallSDK`` so the default capability
        provider evaluates real capabilities and containment revokes
        them through the SDK's own registry."""

        from firewall.sdk import FirewallSDK
        from firewall.containment import ContainmentController

        if not isinstance(sdk, FirewallSDK):
            raise DefenseError("sdk must be a FirewallSDK")

        with self._lock:
            self._sdk = sdk
            self._capability_provider = self._sdk_capability(sdk)
            if isinstance(self._containment, _InertContainment):
                self._containment = ContainmentController(
                    sdk,
                    recorder=self._recorder,
                    authorizer=lambda: True,
                    clock=self._clock,
                )

    def _sdk_capability(
        self, sdk
    ) -> Callable[[str], tuple[bool, str]]:
        def provider(agent: str) -> tuple[bool, str]:
            registry = sdk.known_capabilities()
            live = [
                cap
                for cap in registry.values()
                if cap.agent_id == agent
                and not sdk.is_effectively_revoked(cap)
            ]
            if not live:
                return False, "no live capability"
            return True, f"{len(live)} live capability(ies)"

        return provider

    def evaluate(
        self,
        agent: str,
        *,
        identity_data: Optional[bytes] = None,
        identity_signature: Optional[str] = None,
        now: Optional[float] = None,
    ) -> MeshState:
        """Continuously evaluate one agent.

        When ``identity_data``/``identity_signature`` are supplied they
        are verified live against the identity registry; otherwise the
        registry's recorded identity status is used (verification of a
        presented proof is the stronger check).

        Fail-closed: any error in a provider denies and drops the agent
        to ``restricted`` if it was ``active``.
        """

        now = float(now) if now is not None else float(self._clock())

        with self._lock:
            if agent not in self._identities.agent_ids():
                state = MeshState(
                    agent=agent,
                    state="retired",
                    identity_verified=False,
                    trust_score=0.0,
                    posture="unknown",
                    capability_ok=False,
                    evaluated_at=now,
                    reason="unknown identity",
                )
                self._last[agent] = state
                return state

            identity_verified = self._verify_identity(
                agent, identity_data, identity_signature
            )

            if not identity_verified:
                self._transition(
                    agent,
                    "restricted",
                    actor="mesh",
                    reason="identity verification failed",
                    now=now,
                )
                state = self._build_state(
                    agent,
                    now,
                    identity_verified=False,
                    trust_score=0.0,
                    capability_ok=False,
                    reason="identity verification failed",
                )
                self._last[agent] = state
                return state

            try:
                trust_score, trust_reason = self._trust_provider(agent)
            except Exception as exc:
                trust_score, trust_reason = 0.0, f"trust provider error: {exc}"

            try:
                capability_ok, capability_reason = self._capability_provider(
                    agent
                )
            except Exception as exc:
                capability_ok = False
                capability_reason = f"capability provider error: {exc}"

            posture = (
                self._posture.state(agent).posture
                if self._posture is not None
                else "unknown"
            )

            current = self._states.get(agent, "active")

            if (
                current == "active"
                and (
                    not capability_ok
                    or trust_score < self._quarantine_threshold
                    or posture in ("compromised", "contained", "high_risk")
                )
            ):
                self._transition(
                    agent,
                    "restricted",
                    actor="mesh",
                    reason=(
                        f"automatic restriction: {capability_reason}; "
                        f"trust {trust_score:.2f} ({trust_reason}); "
                        f"posture {posture}"
                    ),
                    now=now,
                )
                current = "restricted"

            if (
                current == "restricted"
                and posture == "compromised"
            ):
                self.quarantine(
                    agent,
                    actor="mesh",
                    reason="posture compromised",
                    now=now,
                )
                current = "quarantined"

            state = self._build_state(
                agent,
                now,
                identity_verified=True,
                trust_score=trust_score,
                capability_ok=capability_ok,
                reason=(
                    f"trust {trust_score:.2f} ({trust_reason}); "
                    f"{capability_reason}"
                ),
                posture=posture,
                state=current,
            )
            self._last[agent] = state
            return state

    def _verify_identity(
        self,
        agent: str,
        data: Optional[bytes],
        signature: Optional[str],
    ) -> bool:
        if data is None or signature is None:
            identity = self._identities.get(agent)
            return identity is not None and identity.status == "active"
        if not isinstance(data, (bytes, bytearray)):
            return False
        try:
            return self._identities.verify(
                agent, bytes(data), signature
            )
        except Exception:
            return False

    def _build_state(
        self,
        agent: str,
        now: float,
        *,
        identity_verified: bool,
        trust_score: float,
        capability_ok: bool,
        reason: str,
        posture: str = "unknown",
        state: Optional[str] = None,
    ) -> MeshState:
        current = state or self._states.get(agent, "active")
        return MeshState(
            agent=agent,
            state=current,
            identity_verified=identity_verified,
            trust_score=trust_score,
            posture=posture,
            capability_ok=capability_ok,
            evaluated_at=now,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Lifecycle: quarantine / recover / re-enter
    # ------------------------------------------------------------------

    def quarantine(
        self,
        agent: str,
        *,
        actor: str = "operator",
        reason: str = "",
        now: Optional[float] = None,
    ) -> MeshTransition:
        """Quarantine an agent: revoke every capability it holds through
        the containment controller and move it to ``quarantined``."""

        if not isinstance(agent, str) or not agent.strip():
            raise DefenseError("agent is required")
        if not isinstance(reason, str) or not reason.strip():
            raise DefenseError("reason is required for quarantine")

        now = float(now) if now is not None else float(self._clock())

        with self._lock:
            identity = self._identities.get(agent)
            if identity is None:
                raise DefenseError(f"unknown identity: {agent}")

            # Record exactly which authority this quarantine suspends,
            # before anything is revoked. Re-entry may restore only
            # this set - never authority that was already revoked.
            self._contained_authority[agent] = self._snapshot_authority(
                agent
            )

            if isinstance(self._containment, ContainmentController):
                try:
                    self._containment.apply(
                        ContainmentAction.QUARANTINE_AGENT,
                        agent,
                        actor=actor,
                        reason="defense mesh: " + reason,
                    )
                except ContainmentError as exc:
                    # Fail closed. A containment failure must not leave
                    # the agent holding live authority just because the
                    # controller refused the transition, so the mesh
                    # revokes the snapshot itself before recording the
                    # quarantine. Nothing may be restored afterwards
                    # either: what this quarantine could not suspend
                    # through the controller, it must not hand back.
                    self._hard_revoke(agent)
                    self._contained_authority.pop(agent, None)
                    self._transition(
                        agent,
                        "quarantined",
                        actor=actor,
                        reason=f"quarantine (containment error: {exc})",
                        now=now,
                    )
                    self._save()
                    return self._transitions[agent][-1]

            self._transition(
                agent,
                "quarantined",
                actor=actor,
                reason=reason,
                now=now,
            )
            self._save()
            return self._transitions[agent][-1]

    def recover(
        self,
        agent: str,
        *,
        actor: str = "operator",
        reason: str = "",
        now: Optional[float] = None,
    ) -> MeshTransition:
        """Begin recovery: only valid from ``quarantined``."""

        if not isinstance(reason, str) or not reason.strip():
            raise DefenseError("reason is required for recovery")

        now = float(now) if now is not None else float(self._clock())

        with self._lock:
            current = self._states.get(agent, "active")
            if current != "quarantined":
                raise DefenseError(
                    f"cannot recover an agent in state {current!r}; "
                    "only quarantined agents can begin recovery"
                )
            self._recovery_started[agent] = now
            self._transition(
                agent,
                "recovering",
                actor=actor,
                reason=reason,
                now=now,
            )
            # Authority stays suspended. ``recovering`` is an
            # investigation state, not a cleared one: restoring
            # authority here would make the agent operational before
            # re-entry verified identity, posture, and recovery
            # freshness -- and a denied re-entry would leave it
            # operational anyway. Restoration happens in ``reenter``.
            self._save()
            return self._transitions[agent][-1]

    def reenter(
        self,
        agent: str,
        *,
        actor: str = "operator",
        reason: str = "",
        now: Optional[float] = None,
    ) -> MeshTransition:
        """Re-entry: verifies identity, posture, and recovery freshness
        before returning the agent to ``active``.

        The agent must be ``recovering``; recovery must not have
        expired (``recovery_ttl``); identity must be active; posture
        must be healthy/degraded/unknown (never compromised); and the
        capability provider must report the agent can act again.
        """

        if not isinstance(reason, str) or not reason.strip():
            raise DefenseError("reason is required for re-entry")

        now = float(now) if now is not None else float(self._clock())

        with self._lock:
            current = self._states.get(agent, "active")
            if current != "recovering":
                raise DefenseError(
                    f"cannot re-enter from state {current!r}; "
                    "agent must be recovering"
                )

            identity = self._identities.get(agent)
            if identity is None or identity.status != "active":
                raise DefenseError(
                    f"re-entry denied: identity is not active for {agent}"
                )

            started = self._recovery_started.get(agent, 0.0)
            if now - started > self._recovery_ttl:
                self._transition(
                    agent,
                    "quarantined",
                    actor="mesh",
                    reason="recovery window expired; re-quarantined",
                    now=now,
                )
                self._save()
                raise DefenseError(
                    "re-entry denied: recovery window expired"
                )

            if self._posture is not None:
                posture = self._posture.state(agent).posture
                if posture in (
                    "compromised",
                    "contained",
                    "high_risk",
                    "suspicious",
                ):
                    raise DefenseError(
                        f"re-entry denied: posture is {posture}"
                    )

            # Identity, recovery freshness, and posture have all been
            # verified, so the authority this mesh's quarantine
            # suspended may come back. It is restored *before* the
            # capability check because the default provider reports
            # "can act" only while the agent holds live authority --
            # asking first would be circular. A provider that still
            # denies means the agent must not come back, so everything
            # this re-entry made live is suspended again: a denied
            # re-entry never leaves authority live.
            before = set(self._live_authority(agent))
            self._resume_containment(agent, actor=actor, reason=reason)
            self._restore_authority(agent)
            restored = tuple(
                capability
                for fingerprint, capability in self._live_authority(
                    agent
                ).items()
                if fingerprint not in before
            )

            try:
                capability_ok, capability_reason = self._capability_provider(
                    agent
                )
            except Exception:
                capability_ok = False
                capability_reason = "capability provider error"

            if not capability_ok:
                self._suspend_authority(agent, restored)
                raise DefenseError(
                    f"re-entry denied: {capability_reason}"
                )

            self._transition(
                agent,
                "active",
                actor=actor,
                reason=reason,
                now=now,
            )
            self._recovery_started.pop(agent, None)
            self._save()
            return self._transitions[agent][-1]

    def retire(
        self,
        agent: str,
        *,
        actor: str = "operator",
        reason: str = "",
        now: Optional[float] = None,
    ) -> MeshTransition:
        if not isinstance(reason, str) or not reason.strip():
            raise DefenseError("reason is required for retirement")
        now = float(now) if now is not None else float(self._clock())
        with self._lock:
            self._transition(
                agent,
                "retired",
                actor=actor,
                reason=reason,
                now=now,
            )
            self._save()
            return self._transitions[agent][-1]

    # ------------------------------------------------------------------
    # Transitions (audited)
    # ------------------------------------------------------------------

    def _transition(
        self,
        agent: str,
        to_state: str,
        *,
        actor: str,
        reason: str,
        now: float,
    ) -> None:
        if to_state not in MESH_STATES:
            raise DefenseError(f"unknown mesh state: {to_state}")

        self._seq += 1
        current = self._states.get(agent, "active")
        self._states[agent] = to_state

        attestation = self._sign_transition(
            agent, current, to_state, actor, reason, now
        )

        transition = MeshTransition(
            agent=agent,
            from_state=current,
            to_state=to_state,
            actor=actor,
            reason=reason,
            timestamp=now,
            attestation=attestation,
            event_seq=self._seq,
        )
        self._transitions.setdefault(agent, []).append(transition)

        if self._recorder is not None:
            try:
                from firewall.recorder import EventType

                self._recorder.record(
                    EventType.SECURITY_STATE,
                    {
                        "change": f"mesh:{to_state}",
                        "agent": agent,
                        "from": current,
                        "actor": actor,
                        "reason": reason,
                    },
                    agent=agent,
                )
            except Exception:
                pass

    def _live_authority(self, agent: str) -> dict[str, Any]:
        """``fingerprint -> capability`` for the agent's live authority."""

        sdk = getattr(self, "_sdk", None)
        if sdk is None:
            return {}

        live: dict[str, Any] = {}
        try:
            registry = sdk.known_capabilities()
            for fingerprint, capability in list(registry.items()):
                if capability.agent_id != agent:
                    continue
                if sdk.is_effectively_revoked(capability):
                    continue
                live[fingerprint] = capability
        except Exception:
            return live
        return live

    def _snapshot_authority(
        self, agent: str
    ) -> tuple[dict[str, Any], ...]:
        """Record the authority a quarantine is about to suspend.

        Only capabilities that are live *right now* are recorded.
        Authority that was already revoked - directly, or through a
        revoked ancestor - is deliberately excluded: quarantine did not
        take it away, so recovery has no business giving it back.
        """

        sdk = getattr(self, "_sdk", None)
        if sdk is None:
            return ()

        records: list[dict[str, Any]] = []
        for fingerprint, capability in self._live_authority(agent).items():
            records.append(
                {
                    "agent": capability.agent_id,
                    "capability": capability.capability,
                    "constraints": dict(capability.constraints or {}),
                    "issuer": capability.issuer,
                    "tool": capability.tool,
                    "fingerprint": fingerprint,
                    "parent": self._parent_fingerprint(sdk, fingerprint),
                }
            )
        return tuple(records)

    @staticmethod
    def _parent_fingerprint(sdk, fingerprint: str) -> Optional[str]:
        """The immediate delegation parent of ``fingerprint``, if any."""

        try:
            chain = list(sdk.delegation_lineage.chain(fingerprint))
        except Exception:
            return None
        return chain[0] if chain else None

    def _hard_revoke(self, agent: str) -> None:
        """Revoke the agent's live authority directly through the SDK.

        The quarantine backstop for when the containment controller
        cannot act. Quarantine must never return having left the agent
        able to act, whatever the controller's state machine says.
        """

        sdk = getattr(self, "_sdk", None)
        if sdk is None:
            return

        for capability in list(self._live_authority(agent).values()):
            try:
                sdk.revoke(
                    capability,
                    reason="defense mesh quarantine: " + agent,
                )
            except Exception:
                continue

        risk = getattr(sdk, "risk_context", None)
        if risk is not None:
            try:
                risk.record_critical(agent)
            except Exception:
                pass

    def _resume_containment(
        self, agent: str, *, actor: str, reason: str
    ) -> None:
        """Clear the containment posture as part of a verified re-entry.

        This is what resets the elevated risk the quarantine recorded.
        A controller that refuses to clear is left alone: the agent then
        holds no restored authority and the capability check below denies
        the re-entry, which is the safe direction.
        """

        if not isinstance(self._containment, ContainmentController):
            return
        try:
            self._containment.apply(
                ContainmentAction.RECOVER,
                agent,
                actor=actor,
                reason="defense mesh re-entry: " + reason,
            )
        except ContainmentError:
            return
        except Exception:
            return

    def _restore_authority(self, agent: str) -> tuple[Any, ...]:
        """Restore only the authority this mesh's quarantine suspended.

        Re-issuance uses the mesh's own clock for ``issued_at``, so the
        restored capability has a fresh fingerprint and is genuinely
        live - ``FirewallSDK.issue()`` alone would reuse the wall clock
        and re-produce the identical signed payload, which stays
        revoked.

        Three invariants hold over the restored set:

        * it is a subset of what quarantine suspended, so a deliberate
          revocation that predates the quarantine is never resurrected;
        * the delegation lineage is re-registered on the fresh
          fingerprint, so an ancestor revocation keeps binding the
          restored child instead of the child laundering itself into a
          root capability. A record whose ancestor is revoked is not
          restored at all;
        * authority the containment controller already restored is not
          duplicated.

        Returns the capabilities this call issued.
        """

        sdk = getattr(self, "_sdk", None)
        if sdk is None:
            return ()

        pending = self._contained_authority.pop(agent, ())
        held = {
            self._authority_key(capability)
            for capability in self._live_authority(agent).values()
        }
        restored: list[Any] = []

        for record in pending:
            parent = record.get("parent")
            key = self._grant_key(
                record["capability"],
                record.get("tool"),
                record.get("issuer"),
                record.get("constraints"),
            )
            if key in held:
                continue
            try:
                if self._ancestry_revoked(sdk, parent):
                    continue
                capability = sdk.issue(
                    agent=record["agent"],
                    capability=record["capability"],
                    constraints=dict(record.get("constraints") or {}),
                    issuer=record.get("issuer", "trusted-issuer"),
                    tool=record.get("tool"),
                    issued_at=float(self._clock()),
                )
                if parent:
                    sdk.delegation_lineage.register(
                        child_fingerprint=sdk.fingerprint(capability),
                        parent_fingerprint=parent,
                    )
            except Exception:
                # Best effort per capability: a failed re-issue leaves
                # the agent without that authority and the caller's
                # capability check decides whether re-entry proceeds.
                continue
            held.add(key)
            restored.append(capability)

        return tuple(restored)

    @staticmethod
    def _grant_key(
        capability: str,
        tool: Optional[str],
        issuer: Optional[str],
        constraints: Optional[dict],
    ) -> str:
        """Identity of an authority grant, ignoring its fingerprint.

        Serialized rather than tupled: constraint values are arbitrary
        JSON (lists and nested objects included) and a tuple key would
        raise on the unhashable ones.
        """

        try:
            rendered = json.dumps(
                constraints or {}, sort_keys=True, default=repr
            )
        except Exception:
            rendered = repr(constraints)
        return "\x00".join(
            [capability, tool or "", issuer or "", rendered]
        )

    @classmethod
    def _authority_key(cls, capability) -> str:
        """``_grant_key`` for an issued capability."""

        return cls._grant_key(
            capability.capability,
            capability.tool,
            capability.issuer,
            capability.constraints,
        )

    @staticmethod
    def _ancestry_revoked(sdk, parent: Optional[str]) -> bool:
        """Is any ancestor of a restored capability revoked?"""

        if not parent:
            return False
        try:
            if sdk.revocation.is_revoked(parent):
                return True
            for ancestor in sdk.delegation_lineage.chain(parent):
                if sdk.revocation.is_revoked(ancestor):
                    return True
        except Exception:
            # Unable to prove the lineage is clean: fail closed.
            return True
        return False

    def _suspend_authority(
        self, agent: str, capabilities: tuple[Any, ...]
    ) -> None:
        """Undo a re-entry that was denied after authority came back.

        Everything the re-entry made live is revoked again and the
        containment posture is put back, so a denied re-entry leaves the
        agent exactly as contained as it was before it was attempted.
        """

        sdk = getattr(self, "_sdk", None)
        if sdk is None:
            return

        for capability in capabilities:
            try:
                sdk.revoke(
                    capability,
                    reason="defense mesh: re-entry denied",
                )
            except Exception:
                continue

        if isinstance(self._containment, ContainmentController):
            try:
                self._containment.apply(
                    ContainmentAction.QUARANTINE_AGENT,
                    agent,
                    actor="mesh",
                    reason="re-entry denied; containment restored",
                )
                return
            except Exception:
                pass

        risk = getattr(sdk, "risk_context", None)
        if risk is not None:
            try:
                risk.record_critical(agent)
            except Exception:
                pass

    def _sign_transition(
        self,
        agent: str,
        from_state: str,
        to_state: str,
        actor: str,
        reason: str,
        now: float,
    ) -> Optional[dict[str, Any]]:
        if self._attest is None:
            return None
        try:
            attestation = self._attest.issue(
                agent_id=agent,
                subject=f"mesh:{to_state}",
                statement_type="defense_mesh_transition",
                payload={
                    "from": from_state,
                    "to": to_state,
                    "actor": actor,
                    "reason": reason,
                    "timestamp": now,
                },
            )
            return attestation.to_dict()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def state(self, agent: str) -> dict[str, Any]:
        with self._lock:
            current = self._states.get(agent, "active")
            return {
                "agent": agent,
                "state": current,
                "transitions": [
                    t.to_dict()
                    for t in self._transitions.get(agent, [])
                ],
            }

    def last_evaluation(self, agent: str) -> Optional[MeshState]:
        with self._lock:
            return self._last.get(agent)

    def known_agents(self) -> tuple[str, ...]:
        """Every agent identity the mesh is responsible for.

        Used by the immune system's detection loop so the whole
        population is continuously evaluated, not only agents that
        happened to emit signals.
        """

        with self._lock:
            return tuple(self._identities.agent_ids())

    def all_states(self) -> dict[str, Any]:
        with self._lock:
            return {
                agent: self.state(agent)
                for agent in sorted(self._states)
            }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "states": {
                    agent: self._states[agent]
                    for agent in sorted(self._states)
                },
                "transitions": [
                    transition.to_dict()
                    for agent in sorted(self._transitions)
                    for transition in self._transitions[agent]
                ],
                "evaluations": [
                    state.to_dict()
                    for agent in sorted(self._last)
                    for state in [self._last[agent]]
                ],
            }

    def close(self) -> None:
        with self._lock:
            self._save()


class _InertContainment:
    """Stand-in containment controller used when no live SDK is attached.

    Keeps the mesh's quarantine bookkeeping honest without pretending to
    revoke anything; real enforcement belongs to the capability provider.
    """

    def __init__(self, clock: Any = None) -> None:
        self._clock = clock if clock is not None else time.time

    def apply(self, action, agent, *, actor="mesh", reason=""):
        if not isinstance(reason, str) or not reason.strip():
            raise ContainmentError("reason is required")
        return None

    def snapshot(self) -> dict[str, Any]:
        return {"states": {}, "history": []}
