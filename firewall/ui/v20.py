"""v2.0 control-plane projections for the browser console.

Adds identity, passport, provenance, posture, trust, and lab views over
the v2.0 modules. Read-only projections where possible; mutations
(identity create/revoke/rotate, provenance trust) go through the
control plane's bearer-token gate.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.ident import IdentityRegistry
from firewall.passport import PassportBuilder
from firewall.provenance import ProvenanceRegistry


class ControlPlaneV20:
    """v2.0 projections over the identity/provenance/passport modules."""

    def __init__(
        self,
        identity_registry: Optional[IdentityRegistry] = None,
        provenance: Optional[ProvenanceRegistry] = None,
        *,
        state_dir: Optional[str] = None,
    ) -> None:
        self._state_dir = state_dir
        self._identities = identity_registry
        self._provenance = provenance

    # ------------------------------------------------------------------
    # Registries (lazy demo defaults)
    # ------------------------------------------------------------------

    def identities(self) -> IdentityRegistry:
        if self._identities is None:
            self._identities = IdentityRegistry(
                state_path=(
                    f"{self._state_dir}/identities.json"
                    if self._state_dir
                    else None
                )
            )
        return self._identities

    def provenance(self) -> ProvenanceRegistry:
        if self._provenance is None:
            self._provenance = ProvenanceRegistry(
                state_path=(
                    f"{self._state_dir}/provenance.json"
                    if self._state_dir
                    else None
                )
            )
        return self._provenance

    # ------------------------------------------------------------------
    # Identity views
    # ------------------------------------------------------------------

    def identity_view(self) -> dict[str, Any]:
        return self.identities().trust_boundary()

    def create_identity(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        agent = payload.get("agent")
        owner = payload.get("owner", "")
        environment = payload.get("environment", "")
        parent = payload.get("parent_agent")

        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("agent is required")

        identity = self.identities().create(
            agent,
            owner=owner,
            environment=environment,
            parent_agent=parent if isinstance(parent, str) and parent else None,
        )
        return identity.to_dict()

    def revoke_identity(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        agent = payload.get("agent")
        reason = payload.get("reason", "")
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("agent is required")
        identity = self.identities().revoke(agent, reason=reason)
        return identity.to_dict()

    def rotate_identity(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        agent = payload.get("agent")
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("agent is required")
        identity = self.identities().rotate(agent)
        return identity.to_dict()

    # ------------------------------------------------------------------
    # Passport
    # ------------------------------------------------------------------

    def passport_view(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        agent = payload.get("agent")
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("agent is required")

        builder = PassportBuilder(self.identities())
        passport = builder.build(agent)
        verification = builder.verify(passport)

        return {
            "passport": passport.to_dict(),
            "verification": verification,
        }

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    def provenance_view(self) -> dict[str, Any]:
        components = self.provenance().all()
        return {
            "components": [
                {
                    "component_id": component.component_id,
                    "kind": component.kind,
                    "name": component.name,
                    "version": component.version,
                    "status": component.status,
                    "integrity": component.integrity,
                    "dependencies": list(component.dependencies),
                }
                for component in components
            ],
            "suspicious": [
                component.component_id
                for component in self.provenance().suspicious()
            ],
        }

    def register_component(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        kind = payload.get("kind")
        name = payload.get("name")
        version = payload.get("version", "")

        if not isinstance(kind, str) or not kind:
            raise ValueError("kind is required")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name is required")

        component = self.provenance().register(
            kind=kind,
            name=name.strip(),
            version=version,
            integrity=payload.get("integrity", ""),
            dependencies=tuple(payload.get("dependencies") or ()),
        )
        return component.to_dict()

    def trust_component(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        action = payload.get("action")
        component_id = payload.get("component_id")
        reason = payload.get("reason", "")

        if not isinstance(action, str) or action not in (
            "trust",
            "suspect",
            "revoke",
        ):
            raise ValueError("action must be trust/suspect/revoke")
        if not isinstance(component_id, str) or not component_id.strip():
            raise ValueError("component_id is required")

        if action == "trust":
            component = self.provenance().trust(
                component_id, reason=reason
            )
        elif action == "suspect":
            component = self.provenance().suspect(
                component_id, reason=reason
            )
        else:
            component = self.provenance().revoke(
                component_id, reason=reason
            )

        return component.to_dict()
