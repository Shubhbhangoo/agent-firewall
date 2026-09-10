"""v2.0 Supply-Chain Provenance (firewall.provenance).

Tracks security-relevant provenance for the components an agent trusts:
models, tools, MCP servers, skills, plugins, packages, adapters,
configuration, and policies.

Design rules:

* **A name is not trust.** A component becomes trustworthy only through
  recorded provenance (integrity hash, source, dependency tree) and an
  explicit trust decision. Matching an expected name changes nothing.
* **Integrity** is a content digest; if the digest cannot be verified
  the component is ``unknown``/``suspicious``, never silently trusted.
* **Revocation** of a component (or an ancestor in its dependency
  tree) marks the whole subtree untrusted.
* Every record carries ``basis`` (observed / derived / inferred) and
  a status: ``trusted``, ``suspicious``, ``revoked``, or ``unknown``.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

#: Component kinds the registry understands.
COMPONENT_KINDS = (
    "model",
    "tool",
    "mcp_server",
    "skill",
    "plugin",
    "package",
    "adapter",
    "configuration",
    "policy",
)

#: Component trust statuses.
COMPONENT_STATUSES = ("trusted", "suspicious", "revoked", "unknown")


class ProvenanceError(ValueError):
    """Raised for an invalid provenance operation."""


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: str | Path) -> str:
    """Content digest of a file, streamed."""

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class Component:
    """One provenance record for a component."""

    component_id: str
    kind: str
    name: str
    version: str = ""
    source: str = ""
    integrity: str = ""
    status: str = "unknown"
    dependencies: tuple[str, ...] = ()
    registered_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.component_id, str) or not self.component_id.strip():
            raise ProvenanceError("component_id is required")
        if self.kind not in COMPONENT_KINDS:
            raise ProvenanceError(f"unknown component kind: {self.kind}")
        if self.status not in COMPONENT_STATUSES:
            raise ProvenanceError(f"unknown component status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "integrity": self.integrity,
            "status": self.status,
            "dependencies": list(self.dependencies),
            "registered_at": self.registered_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Component":
        if not isinstance(payload, dict):
            raise ProvenanceError("component must be an object")
        return cls(
            component_id=payload.get("component_id"),
            kind=payload.get("kind"),
            name=payload.get("name", ""),
            version=payload.get("version", ""),
            source=payload.get("source", ""),
            integrity=payload.get("integrity", ""),
            status=payload.get("status", "unknown"),
            dependencies=tuple(payload.get("dependencies", ()) or ()),
            registered_at=float(payload.get("registered_at", 0.0)),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


class ProvenanceRegistry:
    """Persistent provenance registry with trust and revocation."""

    def __init__(
        self,
        *,
        state_path: Optional[str | Path] = None,
        clock: Any = None,
    ) -> None:
        self._lock = threading.RLock()
        self._path = Path(state_path) if state_path else None
        self._clock = clock if clock is not None else time.time
        self._components: dict[str, Component] = {}
        self._by_name: dict[str, list[str]] = {}

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
            raise ProvenanceError(
                f"cannot load provenance state: {exc}"
            ) from exc

        for entry in data.get("components", []):
            try:
                component = Component.from_dict(entry)
            except ProvenanceError:
                continue
            self._index(component)

    def _save(self) -> None:
        if self._path is None:
            return

        import os
        import tempfile

        data = {
            "components": [
                component.to_dict()
                for component in self._components.values()
            ]
        }

        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".provenance-state.",
            suffix=".tmp",
            dir=dir_text,
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

    def _index(self, component: Component) -> None:
        self._components[component.component_id] = component
        self._by_name.setdefault(component.name, []).append(
            component.component_id
        )

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        *,
        kind: str,
        name: str,
        version: str = "",
        source: str = "",
        integrity: str = "",
        dependencies: Iterable[str] = (),
        metadata: Optional[dict[str, Any]] = None,
        component_id: Optional[str] = None,
    ) -> Component:
        """Register a component. Status starts ``unknown`` -- trust must
        be granted explicitly."""

        if not isinstance(name, str) or not name.strip():
            raise ProvenanceError("name is required")

        with self._lock:
            for dependency in dependencies:
                if dependency not in self._components:
                    raise ProvenanceError(
                        f"unknown dependency: {dependency}"
                    )

            component = Component(
                component_id=(
                    component_id
                    if component_id is not None
                    else f"{kind}:{name}:{version or '0'}"
                ),
                kind=kind,
                name=name.strip(),
                version=version,
                source=source,
                integrity=integrity,
                status="unknown",
                dependencies=tuple(dependencies),
                registered_at=float(self._clock()),
                metadata=dict(metadata or {}),
            )

            if component.component_id in self._components:
                raise ProvenanceError(
                    f"component already registered: "
                    f"{component.component_id}"
                )

            self._index(component)
            self._save()
            return component

    # ------------------------------------------------------------------
    # Trust
    # ------------------------------------------------------------------

    def trust(
        self,
        component_id: str,
        *,
        reason: str = "",
    ) -> Component:
        """Explicitly trust a component and everything it depends on.

        Granting trust requires the dependency chain to be resolvable;
        an unresolvable dependency stays untrusted.
        """

        with self._lock:
            component = self.require(component_id)

            for dependency in component.dependencies:
                dep = self._components.get(dependency)
                if dep is None or dep.status in ("revoked",):
                    raise ProvenanceError(
                        f"cannot trust {component_id}: dependency "
                        f"{dependency} is missing or revoked"
                    )

            metadata = dict(component.metadata)
            metadata["trust_reason"] = reason
            metadata["trusted_at"] = float(self._clock())

            updated = Component(
                component_id=component.component_id,
                kind=component.kind,
                name=component.name,
                version=component.version,
                source=component.source,
                integrity=component.integrity,
                status="trusted",
                dependencies=component.dependencies,
                registered_at=component.registered_at,
                metadata=metadata,
            )

            self._components[component_id] = updated
            self._save()
            return updated

    def suspect(
        self,
        component_id: str,
        *,
        reason: str = "",
    ) -> Component:
        with self._lock:
            component = self.require(component_id)
            metadata = dict(component.metadata)
            if reason:
                metadata["suspect_reason"] = reason

            updated = Component(
                component_id=component.component_id,
                kind=component.kind,
                name=component.name,
                version=component.version,
                source=component.source,
                integrity=component.integrity,
                status="suspicious",
                dependencies=component.dependencies,
                registered_at=component.registered_at,
                metadata=metadata,
            )
            self._components[component_id] = updated
            self._save()
            return updated

    def revoke(
        self,
        component_id: str,
        *,
        reason: str = "",
    ) -> Component:
        """Revoke a component; its dependents become untrusted too."""

        with self._lock:
            component = self.require(component_id)
            metadata = dict(component.metadata)
            metadata["revoked_at"] = float(self._clock())
            if reason:
                metadata["revoke_reason"] = reason

            updated = Component(
                component_id=component.component_id,
                kind=component.kind,
                name=component.name,
                version=component.version,
                source=component.source,
                integrity=component.integrity,
                status="revoked",
                dependencies=component.dependencies,
                registered_at=component.registered_at,
                metadata=metadata,
            )
            self._components[component_id] = updated

            # Propagate: any component depending on a revoked component
            # (directly or transitively) is no longer trusted.
            for other in self._components.values():
                if other.status != "trusted":
                    continue
                if any(
                    dependency in self._revoked_subtree(component_id)
                    for dependency in other.dependencies
                ):
                    meta = dict(other.metadata)
                    meta["untrusted_reason"] = (
                        f"dependency {component_id} revoked"
                    )
                    self._components[other.component_id] = Component(
                        component_id=other.component_id,
                        kind=other.kind,
                        name=other.name,
                        version=other.version,
                        source=other.source,
                        integrity=other.integrity,
                        status="suspicious",
                        dependencies=other.dependencies,
                        registered_at=other.registered_at,
                        metadata=meta,
                    )

            self._save()
            return updated

    def _revoked_subtree(
        self,
        component_id: str,
    ) -> set[str]:
        """All ids revoked by revoking ``component_id`` (itself + any
        component that depends on it, transitively)."""

        out = {component_id}
        changed = True

        while changed:
            changed = False
            for other in self._components.values():
                if other.component_id in out:
                    continue
                if any(dep in out for dep in other.dependencies):
                    out.add(other.component_id)
                    changed = True

        return out

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_integrity(
        self,
        component_id: str,
        content: bytes,
    ) -> dict[str, Any]:
        """Verify content against the recorded integrity digest.

        Returns ``verified`` / ``failed`` / ``unverifiable`` (no
        digest recorded).
        """

        component = self.get(component_id)

        if component is None:
            return {
                "status": "unverifiable",
                "findings": ["unknown component"],
            }

        if not component.integrity:
            return {
                "status": "unverifiable",
                "findings": ["no integrity digest recorded"],
            }

        digest = sha256_digest(content)

        if digest != component.integrity:
            return {
                "status": "failed",
                "findings": [
                    "content digest does not match the recorded "
                    "integrity"
                ],
            }

        return {
            "status": "verified",
            "findings": [],
        }

    def trust_state(
        self,
        component_id: str,
    ) -> dict[str, Any]:
        """Effective trust state including transitive dependencies."""

        component = self.get(component_id)

        if component is None:
            return {"status": "unknown", "findings": ["unknown component"]}

        if component.status == "revoked":
            return {
                "status": "revoked",
                "findings": ["component revoked"],
            }

        untrusted_deps = [
            dependency
            for dependency in component.dependencies
            if self.get(dependency) is None
            or self.get(dependency).status == "revoked"
        ]

        if untrusted_deps:
            return {
                "status": "suspicious",
                "findings": [
                    "dependency untrusted: " + ", ".join(untrusted_deps)
                ],
            }

        return {
            "status": component.status,
            "findings": [],
        }

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def get(self, component_id: str) -> Optional[Component]:
        with self._lock:
            return self._components.get(component_id)

    def require(self, component_id: str) -> Component:
        component = self.get(component_id)
        if component is None:
            raise ProvenanceError(
                f"unknown component: {component_id}"
            )
        return component

    def by_name(
        self,
        name: str,
    ) -> tuple[Component, ...]:
        with self._lock:
            return tuple(
                self._components[component_id]
                for component_id in self._by_name.get(name, ())
            )

    def for_agent(
        self,
        agent_id: str,
    ) -> tuple[dict[str, Any], ...]:
        """Components referenced by an agent (metadata agent_id match)."""

        return tuple(
            component.to_dict()
            for component in self._components.values()
            if component.metadata.get("agent_id") == agent_id
        )

    def all(self) -> tuple[Component, ...]:
        with self._lock:
            return tuple(self._components.values())

    def suspicious(self) -> tuple[Component, ...]:
        return tuple(
            component
            for component in self.all()
            if component.status in ("suspicious", "revoked")
        )

    def close(self) -> None:
        with self._lock:
            self._save()
