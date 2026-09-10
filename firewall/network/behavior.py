"""Behavioral security intelligence (v1.9).

A deterministic, explainable detection engine over recorded security
history. Every detection answers the five questions the mission demands:

* **what happened** (``title``),
* **why it was detected** (``rule`` + ``explanation``),
* **supporting evidence** (event sequences in specific artifacts),
* **confidence/severity** (``severity``, low/medium/high/critical),
* **affected entities** (``agents``, ``capabilities``, ``tools``),
* **recommended response** (``response``).

The engine is deliberately conservative: rules are deterministic
counters and sequence checks over *observed* events. There is no magic
AI scoring. Where a signal is inherently heuristic the finding is
marked ``inferred`` and the rule says so -- inference is never
presented as observation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from firewall.network.correlation import CorrelationIndex
from firewall.network.model import Provenance
from firewall.recorder.events import EventType, SecurityEvent
from firewall.verify import verify_artifact


class BehaviorError(ValueError):
    """Raised for a malformed detection request."""


@dataclass(frozen=True)
class Detection:
    """One behavioral finding, fully explainable."""

    rule_id: str
    title: str
    severity: str
    explanation: str
    evidence: tuple[dict[str, Any], ...]
    agents: tuple[str, ...]
    capabilities: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    response: str = ""
    basis: str = Provenance.INFERRED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "explanation": self.explanation,
            "evidence": [
                dict(entry) for entry in self.evidence
            ],
            "agents": list(self.agents),
            "capabilities": list(self.capabilities),
            "tools": list(self.tools),
            "response": self.response,
            "basis": self.basis,
        }


# ----------------------------------------------------------------------
# Evidence helpers
# ----------------------------------------------------------------------


def _evidence(
    artifact_id: str,
    seq: int,
    detail: str = "",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "artifact": artifact_id,
        "event_seq": seq,
    }
    if detail:
        entry["detail"] = detail
    return entry


def _events_of(
    artifact: dict[str, Any],
    artifact_id: str,
) -> list[tuple[str, SecurityEvent]]:
    """(artifact_id, event) pairs, skipping malformed events."""

    out: list[tuple[str, SecurityEvent]] = []

    for entry in artifact.get("events", []):
        if not isinstance(entry, dict):
            continue
        try:
            event = SecurityEvent.from_dict(entry)
        except Exception:
            continue
        out.append((artifact_id, event))

    return out


def _denied_reasons(
    event: SecurityEvent,
) -> str:
    payload = event.payload or {}
    return str(payload.get("reason") or "")


# ----------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------


def rule_repeated_denials(
    artifacts: list[tuple[str, dict[str, Any]]],
    *,
    threshold: int = 5,
) -> list[Detection]:
    """Repeated denied actions: policy-boundary probing or stuck agent."""

    detections: list[Detection] = []
    counts: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for artifact_id, artifact in artifacts:
        for _, event in _events_of(artifact, artifact_id):
            if event.type != EventType.AUTHORIZATION:
                continue
            payload = event.payload or {}
            if payload.get("allowed"):
                continue
            key = (payload.get("agent") or "system", payload.get("action") or "?")
            counts.setdefault(key, []).append(
                _evidence(
                    artifact_id,
                    event.seq,
                    f"denied: {payload.get('reason')}",
                )
            )

    for (agent, action), evidence in counts.items():
        if len(evidence) >= threshold:
            detections.append(
                Detection(
                    rule_id="repeated_denials",
                    title="Repeated denied actions",
                    severity="medium",
                    explanation=(
                        f"{agent} was denied {action} {len(evidence)} "
                        "times. This is consistent with policy-boundary "
                        "probing or a loop the policy is correctly "
                        "blocking."
                    ),
                    evidence=tuple(evidence),
                    agents=(agent,),
                    capabilities=(action,),
                    response=(
                        "observe; if attempts continue, restrict the "
                        "capability or review whether the policy is "
                        "wrongly blocking legitimate work."
                    ),
                )
            )

    return detections


def rule_capability_escalation(
    artifacts: list[tuple[str, dict[str, Any]]],
    *,
    new_capabilities_within: int = 3,
) -> list[Detection]:
    """Rapid capability expansion: many distinct capabilities issued to
    one agent in a short window."""

    detections: list[Detection] = []
    per_agent: dict[str, list[dict[str, Any]]] = {}

    for artifact_id, artifact in artifacts:
        for _, event in _events_of(artifact, artifact_id):
            if event.type != EventType.AUTHORITY_ISSUED:
                continue
            payload = event.payload or {}
            agent = event.agent or payload.get("agent") or "system"
            capability = payload.get("capability") or "?"
            per_agent.setdefault(agent, []).append(
                {
                    "capability": capability,
                    "artifact": artifact_id,
                    "seq": event.seq,
                    "timestamp": event.timestamp,
                }
            )

    for agent, entries in per_agent.items():
        caps = {entry["capability"] for entry in entries}

        if len(caps) >= new_capabilities_within:
            detections.append(
                Detection(
                    rule_id="capability_escalation",
                    title="Rapid capability expansion",
                    severity="medium",
                    explanation=(
                        f"{agent} received {len(caps)} distinct "
                        "capabilities in the recorded window. Fast "
                        "authority growth is a common prelude to "
                        "privilege escalation; verify each issuance."
                    ),
                    evidence=tuple(
                        _evidence(
                            entry["artifact"],
                            entry["seq"],
                            f"issued {entry['capability']}",
                        )
                        for entry in entries
                    ),
                    agents=(agent,),
                    capabilities=tuple(sorted(caps)),
                    response=(
                        "review issuances; attenuate or revoke any "
                        "capability not required by the current task."
                    ),
                )
            )

    return detections


def rule_unexpected_delegation(
    artifacts: list[tuple[str, dict[str, Any]]],
) -> list[Detection]:
    """Delegation to agents with no recorded identity or session of
    their own: authority moved to an unknown entity."""

    known_agents: set[str] = set()
    delegations: list[dict[str, Any]] = []

    for artifact_id, artifact in artifacts:
        for _, event in _events_of(artifact, artifact_id):
            payload = event.payload or {}
            if event.type == EventType.AUTHORIZATION:
                known_agents.add(
                    event.agent or payload.get("agent") or "system"
                )
            if event.type == EventType.AUTHORITY_ISSUED:
                known_agents.add(
                    event.agent or payload.get("agent") or "system"
                )
            if event.type == EventType.AUTHORITY_DELEGATED:
                delegations.append(
                    {
                        "artifact": artifact_id,
                        "seq": event.seq,
                        "from": event.agent or payload.get("agent") or "?",
                        "to": payload.get("delegatee") or "?",
                        "capability": payload.get("capability") or "?",
                    }
                )

    detections: list[Detection] = []

    for entry in delegations:
        if entry["to"] not in known_agents:
            detections.append(
                Detection(
                    rule_id="unexpected_delegation",
                    title="Authority delegated to an unknown agent",
                    severity="high",
                    explanation=(
                        f"{entry['from']} delegated "
                        f"{entry['capability']} to {entry['to']}, "
                        "which has no recorded session or capability of "
                        "its own. Authority flowing to an unobserved "
                        "entity warrants investigation."
                    ),
                    evidence=(
                        _evidence(
                            entry["artifact"],
                            entry["seq"],
                        ),
                    ),
                    agents=(entry["from"], entry["to"]),
                    capabilities=(entry["capability"],),
                    response=(
                        "quarantine the recipient until its identity "
                        "and authorization are verified."
                    ),
                )
            )

    return detections


def rule_structural_denials(
    artifacts: list[tuple[str, dict[str, Any]]],
) -> list[Detection]:
    """Structural denials (revoked capability, untrusted issuer,
    broken chain) -- signs of tampering or stale authority."""

    structural = {
        "capability_revoked",
        "untrusted_issuer",
        "delegation_chain_error",
        "delegation_depth_exceeded",
        "missing_ancestor",
        "revoked_ancestor",
        "risk_state_revoked",
    }

    detections: list[Detection] = []

    for artifact_id, artifact in artifacts:
        for _, event in _events_of(artifact, artifact_id):
            if event.type != EventType.AUTHORIZATION:
                continue
            payload = event.payload or {}
            if payload.get("allowed"):
                continue
            reason = _denied_reasons(event)

            if reason not in structural:
                continue

            detections.append(
                Detection(
                    rule_id="structural_denial",
                    title="Authorization blocked by structural failure",
                    severity="high",
                    explanation=(
                        f"{payload.get('agent') or event.agent} was "
                        f"denied {payload.get('action')}: {reason}. "
                        "A revoked, untrusted, or broken authority "
                        "chain is a containment or tampering signal."
                    ),
                    evidence=(
                        _evidence(
                            artifact_id,
                            event.seq,
                            reason,
                        ),
                    ),
                    agents=(
                        payload.get("agent") or event.agent or "system",
                    ),
                    capabilities=(payload.get("action") or "?",),
                    response=(
                        "verify the authority chain; quarantine the "
                        "agent if the denial is unexpected."
                    ),
                )
            )

    return detections


def rule_credential_shaped_access(
    artifacts: list[tuple[str, dict[str, Any]]],
) -> list[Detection]:
    """Accesses to credential-like resources: an agent reaching for
    keys, tokens, or credential stores."""

    sensitive_markers = (
        ".ssh/",
        "id_rsa",
        "id_ed25519",
        "authorized_keys",
        "credentials",
        ".aws/",
        "secrets",
        "token",
        "password",
        ".env",
        "keyring",
        "shadow",
    )

    detections: list[Detection] = []

    for artifact_id, artifact in artifacts:
        for _, event in _events_of(artifact, artifact_id):
            if event.type != EventType.AUTHORIZATION:
                continue
            payload = event.payload or {}
            request = payload.get("request") or {}
            if not isinstance(request, dict):
                continue

            target = ""
            for key in ("path", "resource", "url", "uri"):
                value = request.get(key)
                if isinstance(value, str):
                    target = value
                    break

            lowered = target.lower()

            if any(
                marker in lowered
                for marker in sensitive_markers
            ):
                detections.append(
                    Detection(
                        rule_id="credential_shaped_access",
                        title="Access to credential-like resource",
                        severity="high",
                        explanation=(
                            f"{payload.get('agent') or event.agent} "
                            f"requested {target!r}. Credential-shaped "
                            "resource names warrant verification even "
                            "when the access was allowed."
                        ),
                        evidence=(
                            _evidence(
                                artifact_id,
                                event.seq,
                                f"{payload.get('action')} {target}",
                            ),
                        ),
                        agents=(
                            payload.get("agent") or event.agent or "system",
                        ),
                        response=(
                            "verify the request was legitimate; "
                            "otherwise revoke the capability and "
                            "quarantine the agent."
                        ),
                    )
                )

    return detections


# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------


def _verification_ok(status: str) -> bool:
    return status in ("verified", "redacted")


def analyze_artifacts(
    artifacts: Iterable[dict[str, Any]],
    *,
    include_flagged: bool = False,
) -> list[Detection]:
    """Run every rule over the artifacts.

    Only verified/redacted artifacts contribute by default. A failed
    artifact's events are never used as behavioral evidence.
    """

    accepted: list[tuple[str, dict[str, Any]]] = []

    for artifact in artifacts:
        report = verify_artifact(artifact)
        artifact_id = str(
            artifact.get("session", {}).get("id", "artifact")
        )

        if report.status in ("verified", "redacted"):
            accepted.append((artifact_id, artifact))
        elif include_flagged:
            accepted.append((artifact_id, artifact))

    return analyze_indexed(accepted)


def analyze_indexed(
    artifacts: list[tuple[str, dict[str, Any]]],
) -> list[Detection]:
    """Run rules over (artifact_id, artifact) pairs."""

    detections: list[Detection] = []

    detections.extend(
        rule_repeated_denials(artifacts)
    )
    detections.extend(
        rule_capability_escalation(artifacts)
    )
    detections.extend(
        rule_unexpected_delegation(artifacts)
    )
    detections.extend(
        rule_structural_denials(artifacts)
    )
    detections.extend(
        rule_credential_shaped_access(artifacts)
    )

    return detections


def analyze_index(
    index: CorrelationIndex,
) -> list[Detection]:
    """Run rules over a :class:`CorrelationIndex`'s verified artifacts."""

    artifacts = [
        (artifact_id, index.artifact(artifact_id))
        for artifact_id in index.verified_ids()
        if index.artifact(artifact_id) is not None
    ]

    return analyze_indexed(artifacts)
