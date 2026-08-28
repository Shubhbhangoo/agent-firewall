"""v2.0 Agent Security Passport (firewall.passport).

A deterministic, versioned, exportable, independently verifiable summary
of an agent's security identity and posture. A passport answers:

* who is this agent (identity, owner, environment, status, key),
* what it can currently do (active tasks, delegated authority,
  capabilities),
* what it trusts (tool/model/supply-chain provenance),
* its security posture and behavioral signals,
* its reach / attack paths / incidents / containment state,
* and carries a signed integrity check over the whole document.

The passport never contains private keys. It is signed by the agent
identity key (the registry's ``sign`` over the canonical payload) so an
independent party can verify both the content's integrity and that the
agent's current key produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from firewall.ident import IdentityRegistry

#: Passport format version.
PASSPORT_VERSION = 1


class PassportError(ValueError):
    """Raised for an invalid passport."""


def _canonical(
    identity: dict[str, Any],
    posture: dict[str, Any],
    tasks: list[dict[str, Any]],
    capabilities: list[str],
    delegated: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    reach: dict[str, Any],
    incidents: list[dict[str, Any]],
    containment: dict[str, Any],
) -> bytes:
    """Deterministic payload the passport signature covers."""

    return json.dumps(
        {
            "passport_version": PASSPORT_VERSION,
            "identity": identity,
            "posture": posture,
            "tasks": tasks,
            "capabilities": sorted(capabilities),
            "delegated_authority": delegated,
            "provenance": provenance,
            "reach": reach,
            "incidents": incidents,
            "containment": containment,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class Passport:
    """One agent security passport."""

    identity: dict[str, Any]
    posture: dict[str, Any]
    tasks: tuple[dict[str, Any], ...] = ()
    capabilities: tuple[str, ...] = ()
    delegated_authority: tuple[dict[str, Any], ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()
    reach: dict[str, Any] = field(default_factory=dict)
    incidents: tuple[dict[str, Any], ...] = ()
    containment: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    key_fingerprint: str = ""
    created_at: float = 0.0

    def payload(self) -> bytes:
        return _canonical(
            self.identity,
            self.posture,
            [dict(task) for task in self.tasks],
            list(self.capabilities),
            [dict(entry) for entry in self.delegated_authority],
            [dict(entry) for entry in self.provenance],
            self.reach,
            [dict(entry) for entry in self.incidents],
            self.containment,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "passport_version": PASSPORT_VERSION,
            "identity": dict(self.identity),
            "posture": dict(self.posture),
            "tasks": [dict(task) for task in self.tasks],
            "capabilities": list(self.capabilities),
            "delegated_authority": [
                dict(entry) for entry in self.delegated_authority
            ],
            "provenance": [dict(entry) for entry in self.provenance],
            "reach": dict(self.reach),
            "incidents": [dict(entry) for entry in self.incidents],
            "containment": dict(self.containment),
            "signature": self.signature,
            "key_fingerprint": self.key_fingerprint,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Passport":
        if not isinstance(payload, dict):
            raise PassportError("passport must be an object")
        return cls(
            identity=dict(payload.get("identity", {}) or {}),
            posture=dict(payload.get("posture", {}) or {}),
            tasks=tuple(
                dict(entry) for entry in payload.get("tasks", [])
            ),
            capabilities=tuple(
                str(entry) for entry in payload.get("capabilities", [])
            ),
            delegated_authority=tuple(
                dict(entry)
                for entry in payload.get("delegated_authority", [])
            ),
            provenance=tuple(
                dict(entry) for entry in payload.get("provenance", [])
            ),
            reach=dict(payload.get("reach", {}) or {}),
            incidents=tuple(
                dict(entry) for entry in payload.get("incidents", [])
            ),
            containment=dict(payload.get("containment", {}) or {}),
            signature=payload.get("signature", ""),
            key_fingerprint=payload.get("key_fingerprint", ""),
            created_at=float(payload.get("created_at", 0.0)),
        )


class PassportBuilder:
    """Builds and verifies passports from live registries."""

    def __init__(
        self,
        identity_registry: IdentityRegistry,
        *,
        task_registry=None,
        posture_provider=None,
        graph=None,
        containment_controller=None,
        incident_provider=None,
        provenance_provider=None,
        clock: Any = None,
    ) -> None:
        if not isinstance(identity_registry, IdentityRegistry):
            raise PassportError(
                "identity_registry must be an IdentityRegistry"
            )

        self._identities = identity_registry
        self._tasks = task_registry
        self._posture = posture_provider
        self._graph = graph
        self._containment = containment_controller
        self._incidents = incident_provider
        self._provenance = provenance_provider

        import time

        self._clock = clock if clock is not None else time.time

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(
        self,
        agent_id: str,
    ) -> Passport:
        identity = self._identities.get(agent_id)

        if identity is None:
            raise PassportError(
                f"unknown identity: {agent_id}"
            )

        tasks = self._task_view(agent_id)
        capabilities = self._capability_view(agent_id)
        delegated = self._delegated_view(agent_id)
        posture = self._posture_view(agent_id)
        provenance = self._provenance_view(agent_id)
        reach = self._reach_view(agent_id)
        incidents = self._incident_view(agent_id)
        containment = self._containment_view(agent_id)

        payload = _canonical(
            identity.to_dict(),
            posture,
            tasks,
            capabilities,
            delegated,
            provenance,
            reach,
            incidents,
            containment,
        )

        signature = ""
        key_fingerprint = identity.key_fingerprint

        if identity.status == "active":
            try:
                signature = self._identities.sign(
                    agent_id,
                    payload,
                )
            except Exception:
                signature = ""

        return Passport(
            identity=identity.to_dict(),
            posture=posture,
            tasks=tuple(tasks),
            capabilities=tuple(capabilities),
            delegated_authority=tuple(delegated),
            provenance=tuple(provenance),
            reach=reach,
            incidents=tuple(incidents),
            containment=containment,
            signature=signature,
            key_fingerprint=key_fingerprint,
            created_at=float(self._clock()),
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(
        self,
        passport: Passport,
    ) -> dict[str, Any]:
        """Verify a passport's signature against the recorded identity.

        Returns a status + findings. A passport whose identity is
        unknown, revoked, or retired fails; a missing or invalid
        signature fails; an identity whose key fingerprint does not
        match the passport's fails.
        """

        if not isinstance(passport, Passport):
            return {
                "status": "invalid",
                "findings": ["not a passport"],
            }

        identity_dict = passport.identity or {}
        agent_id = identity_dict.get("agent_id")

        if not isinstance(agent_id, str) or not agent_id:
            return {
                "status": "invalid",
                "findings": ["passport carries no agent_id"],
            }

        identity = self._identities.get(agent_id)

        if identity is None:
            return {
                "status": "unverifiable",
                "findings": [f"unknown identity: {agent_id}"],
            }

        if identity.status in ("revoked", "retired"):
            return {
                "status": "failed",
                "findings": [
                    f"identity is {identity.status}"
                ],
            }

        if (
            passport.key_fingerprint
            and passport.key_fingerprint != identity.key_fingerprint
        ):
            return {
                "status": "failed",
                "findings": [
                    "passport key fingerprint does not match the "
                    "recorded identity key"
                ],
            }

        if not passport.signature:
            return {
                "status": "failed",
                "findings": ["passport is not signed"],
            }

        valid = self._identities.verify(
            agent_id,
            passport.payload(),
            passport.signature,
        )

        if not valid:
            return {
                "status": "failed",
                "findings": [
                    "passport signature does not verify against the "
                    "recorded identity key"
                ],
            }

        return {
            "status": "verified",
            "findings": [],
            "agent_id": agent_id,
            "key_fingerprint": identity.key_fingerprint,
        }

    # ------------------------------------------------------------------
    # Views (all read-only; missing providers degrade to empty)
    # ------------------------------------------------------------------

    def _task_view(
        self,
        agent_id: str,
    ) -> list[dict[str, Any]]:
        if self._tasks is None:
            return []

        tasks = self._tasks.tasks_for_agent(agent_id)

        return [
            {
                "task_id": task.task_id,
                "status": task.status,
                "active": self._tasks.is_active(task.task_id),
                "permissions": dict(task.permissions),
                "parent_task": task.parent_task,
                "expires_at": task.expires_at,
            }
            for task in tasks
        ]

    def _capability_view(
        self,
        agent_id: str,
    ) -> list[str]:
        if self._graph is None:
            return []

        try:
            reachable = self._graph.reachable(agent_id)
            return list(reachable.capabilities)
        except Exception:
            return []

    def _delegated_view(
        self,
        agent_id: str,
    ) -> list[dict[str, Any]]:
        if self._graph is None:
            return []

        try:
            reachable = self._graph.reachable(agent_id)
            return [
                {
                    "capability": capability,
                    "basis": "derived",
                }
                for capability in reachable.capabilities
            ]
        except Exception:
            return []

    def _posture_view(
        self,
        agent_id: str,
    ) -> dict[str, Any]:
        if self._posture is None:
            return {"posture": "unknown", "basis": "no_provider"}

        try:
            return self._posture.get(agent_id)
        except Exception:
            return {"posture": "unknown", "basis": "provider_error"}

    def _provenance_view(
        self,
        agent_id: str,
    ) -> list[dict[str, Any]]:
        if self._provenance is None:
            return []

        try:
            return list(self._provenance.for_agent(agent_id))
        except Exception:
            return []

    def _reach_view(
        self,
        agent_id: str,
    ) -> dict[str, Any]:
        if self._graph is None:
            return {}

        try:
            return self._graph.reachable(agent_id).to_dict()
        except Exception:
            return {}

    def _incident_view(
        self,
        agent_id: str,
    ) -> list[dict[str, Any]]:
        if self._incidents is None:
            return []

        try:
            return list(self._incidents.for_agent(agent_id))
        except Exception:
            return []

    def _containment_view(
        self,
        agent_id: str,
    ) -> dict[str, Any]:
        if self._containment is None:
            return {"state": "active"}

        try:
            state = self._containment.state(agent_id)
            return {
                "state": state.value,
            }
        except Exception:
            return {"state": "unknown"}

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(
        self,
        passport: Passport,
        path: str,
    ) -> str:
        import json as _json
        from pathlib import Path

        target = Path(path)

        if target.parent and str(target.parent) != ".":
            target.parent.mkdir(parents=True, exist_ok=True)

        target.write_text(
            _json.dumps(
                passport.to_dict(),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        return str(target)

    def load(
        self,
        path: str,
    ) -> Passport:
        import json as _json
        from pathlib import Path

        try:
            payload = _json.loads(
                Path(path).read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise PassportError(
                f"cannot read passport: {exc}"
            ) from exc

        return Passport.from_dict(payload)
