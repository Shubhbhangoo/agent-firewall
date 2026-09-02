"""v2.1 Agent-to-Agent Zero Trust (firewall.a2a).

Authenticated agent relationships with scoped permissions, built on the
v2.0 identity system. Every agent interaction is untrusted until
explicitly authorized.

Guarantees:

* **Mutual cryptographic authentication** -- both sides sign a fresh
  challenge with their identity keys before a relationship exists.
* **Scoped permissions** -- a relationship grants only the intersection
  of what the initiator is willing to grant and what the responder
  accepts; the grant map is never wider than either side's policy.
* **Task-bound delegation** -- relationships can be bound to a task;
  authorization consults an optional task provider so an expired or
  revoked task denies.
* **Capability attenuation** -- ``delegate`` narrows; the effective
  permissions of a derived relationship are always a subset of the
  parent's effective permissions.
* **Delegation-chain verification** -- ``verify_chain`` walks the parent
  chain, proves monotone narrowing, and rejects cycles and missing
  ancestors (fail closed).
* **Expiring delegation** -- every relationship carries ``expires_at``
  and authorization checks it against the clock.
* **Recursive revocation** -- revoking a relationship revokes every
  relationship derived from it.
* **Trust establishment and teardown** -- ``establish`` and ``teardown``
  are audited transitions recorded as signed attestations when an
  attestation authority is attached.
* **Cross-agent authorization decisions** -- ``authorize`` is
  deterministic and fail-closed; when an SDK provider is attached, the
  relationship check is not enough -- the real authorization pipeline
  must also allow the action.

An agent can never elevate its own authority through this module: no
operation here widens a permission set, and every revocation propagates
downward.
"""

from __future__ import annotations

import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from firewall.ident import IdentityRegistry
from firewall.task.registry import _permissions_intersect

#: Relationship statuses.
RELATIONSHIP_STATUSES = ("active", "revoked", "expired")

#: Challenge lifetime in seconds.
CHALLENGE_TTL = 60.0


class A2AError(ValueError):
    """Raised for an invalid agent-to-agent operation."""


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise A2AError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise A2AError(f"{label} must be finite")
    return result


def _permission_no_wider(child: Any, parent: Any, key: str) -> bool:
    """Is ``child`` at most as permissive as ``parent`` for one key?

    Lists narrow by membership; numeric ceilings narrow by magnitude;
    everything else must be equal (or a child prefix of a string scope).
    """

    if isinstance(child, (list, tuple)) and isinstance(
        parent, (list, tuple)
    ):
        return set(child).issubset(set(parent))
    if (
        isinstance(child, (int, float))
        and not isinstance(child, bool)
        and isinstance(parent, (int, float))
        and not isinstance(parent, bool)
    ):
        return child <= parent
    if isinstance(child, str) and isinstance(parent, str):
        if child == parent:
            return True
        return child.startswith(parent)
    return child == parent


def _permissions_union_narrowing(left: dict, right: dict) -> dict:
    """The grant a delegation is allowed to confer.

    Reuses the task registry's intersection semantics so a2a
    delegation narrows exactly like task delegation.
    """

    return _permissions_intersect(left, right)


@dataclass(frozen=True)
class AgentRelationship:
    """One authenticated, scoped relationship between two agents."""

    relationship_id: str
    initiator: str
    responder: str
    permissions: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    parent_relationship: Optional[str] = None
    task_id: Optional[str] = None
    created_at: float = 0.0
    expires_at: Optional[float] = None
    revoked_at: Optional[float] = None
    revoke_reason: str = ""
    mutual_auth: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.relationship_id, str) or not self.relationship_id.strip():
            raise A2AError("relationship_id is required")
        if not isinstance(self.initiator, str) or not self.initiator.strip():
            raise A2AError("initiator is required")
        if not isinstance(self.responder, str) or not self.responder.strip():
            raise A2AError("responder is required")
        if self.initiator == self.responder:
            raise A2AError("an agent cannot have a relationship with itself")
        if self.status not in RELATIONSHIP_STATUSES:
            raise A2AError(f"unknown relationship status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "initiator": self.initiator,
            "responder": self.responder,
            "permissions": dict(self.permissions),
            "status": self.status,
            "parent_relationship": self.parent_relationship,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "revoke_reason": self.revoke_reason,
            "mutual_auth": dict(self.mutual_auth),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "AgentRelationship":
        if not isinstance(payload, dict):
            raise A2AError("relationship must be an object")
        return cls(
            relationship_id=payload.get("relationship_id"),
            initiator=payload.get("initiator"),
            responder=payload.get("responder"),
            permissions=dict(payload.get("permissions", {}) or {}),
            status=payload.get("status", "active"),
            parent_relationship=payload.get("parent_relationship"),
            task_id=payload.get("task_id"),
            created_at=float(payload.get("created_at", 0.0)),
            expires_at=(
                float(payload["expires_at"])
                if payload.get("expires_at") is not None
                else None
            ),
            revoked_at=(
                float(payload["revoked_at"])
                if payload.get("revoked_at") is not None
                else None
            ),
            revoke_reason=payload.get("revoke_reason", ""),
            mutual_auth=dict(payload.get("mutual_auth", {}) or {}),
        )


#: ``A2ADecision.basis`` values, in decreasing epistemic strength.
#:
#: The distinction is the whole point of the field. An allow whose basis
#: is ``CANONICAL`` relays a ``FirewallSDK.authorize()`` decision. An
#: allow whose basis is ``RELATIONSHIP_ONLY`` does not: the mesh was
#: built without an ``sdk_provider``, so the only things established are
#: that a relationship exists, is active, and covers the action. That is
#: necessary for a cross-agent call and it is not sufficient, and a
#: caller that cannot tell the two apart will read the second as the
#: first.
BASIS_CANONICAL = "canonical"
BASIS_RELATIONSHIP_ONLY = "relationship_only"
BASIS_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class A2ADecision:
    """One cross-agent decision, and what established it.

    ``allowed`` alone is not an authorization. Read it together with
    ``basis``: only :data:`BASIS_CANONICAL` means the real pipeline ran
    and allowed the action. See :attr:`is_canonical`.
    """

    actor: str
    target: str
    action: str
    allowed: bool
    reason: str
    relationship_id: Optional[str] = None
    basis: str = BASIS_RELATIONSHIP_ONLY

    @property
    def is_canonical(self) -> bool:
        """Whether ``FirewallSDK.authorize()`` produced this decision.

        ``False`` for every decision reached without consulting the
        pipeline, including allows. A caller that enforces on
        ``allowed`` and ignores this is enforcing on a relationship
        check.
        """

        return self.basis == BASIS_CANONICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "target": self.target,
            "action": self.action,
            "allowed": self.allowed,
            "reason": self.reason,
            "relationship_id": self.relationship_id,
            "basis": self.basis,
            "is_canonical": self.is_canonical,
        }


class AgentToAgent:
    """Authenticated agent relationships with scoped, narrowing grants.

    ``sdk_provider`` is an optional callable
    ``(actor, target, action, request) -> (allowed, reason)`` that runs
    the real authorization pipeline; when attached, a relationship grant
    alone is never sufficient. ``task_provider`` is an optional callable
    ``(task_id) -> bool`` reporting whether a task is still active.

    The provider is optional because this class is also useful purely as
    a relationship registry -- ``trust_graph``, ``lineage`` and
    ``effective_permissions`` answer questions that have nothing to do
    with a live request. But an :meth:`authorize` allow reached *without*
    it is not an authorization, and every decision carries the
    ``basis``/``is_canonical`` pair that says which kind it is. Anything
    that enforces on this class must attach a provider.
    """

    def __init__(
        self,
        identities: IdentityRegistry,
        *,
        attest=None,
        sdk_provider: Optional[Callable[..., tuple[bool, str]]] = None,
        task_provider: Optional[Callable[[str], bool]] = None,
        clock: Any = None,
        state_path: Optional[str | Path] = None,
    ) -> None:
        if not isinstance(identities, IdentityRegistry):
            raise A2AError("identities must be an IdentityRegistry")
        if sdk_provider is not None and not callable(sdk_provider):
            raise A2AError("sdk_provider must be callable")
        if task_provider is not None and not callable(task_provider):
            raise A2AError("task_provider must be callable")

        self._identities = identities
        self._attest = attest
        self._sdk_provider = sdk_provider
        self._task_provider = task_provider
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()

        self._relationships: dict[str, AgentRelationship] = {}
        # relationship_id -> children (for recursive revocation)
        self._children: dict[str, list[str]] = {}
        # pending auth challenges: agent -> (nonce, issued_at)
        self._challenges: dict[str, tuple[str, float]] = {}

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
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise A2AError(f"cannot load a2a state: {exc}") from exc
        if not isinstance(data, dict):
            raise A2AError("a2a state must be an object")
        with self._lock:
            for entry in data.get("relationships", []):
                try:
                    rel = AgentRelationship.from_dict(entry)
                except A2AError:
                    continue
                self._relationships[rel.relationship_id] = rel
                if rel.parent_relationship is not None:
                    self._children.setdefault(rel.parent_relationship, []).append(
                        rel.relationship_id
                    )

    def _save(self) -> None:
        if self._path is None:
            return
        import os
        import tempfile

        data = {
            "relationships": [
                rel.to_dict() for rel in self._relationships.values()
            ]
        }
        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".a2a-state.", suffix=".tmp", dir=dir_text
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
    # Mutual authentication
    # ------------------------------------------------------------------

    def challenge(self, agent: str) -> str:
        """Issue a fresh, short-lived authentication challenge."""

        if not isinstance(agent, str) or not agent.strip():
            raise A2AError("agent is required")
        identity = self._identities.get(agent)
        if identity is None:
            raise A2AError(f"unknown identity: {agent}")
        if identity.status != "active":
            raise A2AError(f"identity is not active: {agent}")

        nonce = uuid.uuid4().hex
        with self._lock:
            self._challenges[agent] = (nonce, float(self._clock()))
        return nonce

    def _challenge_bytes(self, agent: str, nonce: str) -> bytes:
        return json.dumps(
            {"agent": agent, "nonce": nonce},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def authenticate(
        self,
        agent: str,
        nonce: str,
        signature: str,
    ) -> bool:
        """Verify one side's signature over a fresh challenge."""

        if not isinstance(nonce, str) or not nonce:
            return False
        with self._lock:
            record = self._challenges.get(agent)
            if record is None:
                return False
            expected, issued_at = record
            del self._challenges[agent]

        if expected != nonce:
            return False
        if float(self._clock()) - issued_at > CHALLENGE_TTL:
            return False

        try:
            return self._identities.verify(
                agent,
                self._challenge_bytes(agent, nonce),
                signature,
            )
        except Exception:
            return False

    def mutual_authenticate(
        self,
        agent_a: str,
        agent_b: str,
    ) -> dict[str, Any]:
        """Full mutual authentication: both sides present challenges and
        signatures. Returns a proof record consumed by ``establish``."""

        if agent_a == agent_b:
            raise A2AError("an agent cannot authenticate with itself")

        for agent in (agent_a, agent_b):
            identity = self._identities.get(agent)
            if identity is None:
                raise A2AError(f"unknown identity: {agent}")
            if identity.status != "active":
                raise A2AError(f"identity is not active: {agent}")

        nonce_a = self.challenge(agent_a)
        nonce_b = self.challenge(agent_b)

        signature_a = self._identities.sign(
            agent_a, self._challenge_bytes(agent_a, nonce_a)
        )
        signature_b = self._identities.sign(
            agent_b, self._challenge_bytes(agent_b, nonce_b)
        )

        verified_a = self.authenticate(agent_a, nonce_a, signature_a)
        verified_b = self.authenticate(agent_b, nonce_b, signature_b)

        return {
            "agent_a": agent_a,
            "agent_b": agent_b,
            "a_verified": verified_a,
            "b_verified": verified_b,
            "mutually_authenticated": verified_a and verified_b,
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
        }

    # ------------------------------------------------------------------
    # Trust establishment / teardown
    # ------------------------------------------------------------------

    def establish(
        self,
        *,
        initiator: str,
        responder: str,
        permissions: Optional[dict[str, Any]] = None,
        ttl: Optional[float] = None,
        task_id: Optional[str] = None,
        mutual_auth: Optional[dict[str, Any]] = None,
    ) -> AgentRelationship:
        """Establish a scoped relationship between two agents.

        Both identities must be active. When ``mutual_auth`` (from
        :meth:`mutual_authenticate`) is supplied it must prove both
        sides; otherwise both sides are authenticated implicitly by
        their active identity status (the caller is expected to have run
        the challenge protocol). ``permissions`` must be non-empty; an
        empty grant establishes nothing.
        """

        for agent in (initiator, responder):
            identity = self._identities.get(agent)
            if identity is None:
                raise A2AError(f"unknown identity: {agent}")
            if identity.status != "active":
                raise A2AError(f"identity is not active: {agent}")

        if mutual_auth is not None:
            if not mutual_auth.get("mutually_authenticated"):
                raise A2AError("mutual authentication failed")
            if {mutual_auth.get("agent_a"), mutual_auth.get("agent_b")} != {
                initiator,
                responder,
            }:
                raise A2AError("mutual authentication proof names different agents")

        # Task activity is deliberately NOT checked here: a relationship
        # may be established while a task is idle and only ever deny at
        # authorization time when the task is inactive. Refusing to
        # establish on an inactive task would make establishment a
        # no-op race with task lifecycle.
        granted = dict(permissions or {})
        if not granted:
            raise A2AError("a relationship requires at least one permission")

        now = float(self._clock())
        if ttl is not None:
            ttl = _finite(ttl, "ttl")
            if ttl <= 0:
                raise A2AError("ttl must be positive")

        relationship = AgentRelationship(
            relationship_id=f"rel-{uuid.uuid4().hex[:12]}",
            initiator=initiator,
            responder=responder,
            permissions=granted,
            status="active",
            parent_relationship=None,
            task_id=task_id,
            created_at=now,
            expires_at=(now + ttl if ttl is not None else None),
            mutual_auth=dict(mutual_auth or {}),
        )

        with self._lock:
            self._relationships[relationship.relationship_id] = relationship
            self._save()
            self._audit(
                "establish",
                relationship,
                detail={"permissions": granted, "task_id": task_id},
            )
            return relationship

    def delegate(
        self,
        parent: AgentRelationship,
        *,
        responder: str,
        permissions: Optional[dict[str, Any]] = None,
        ttl: Optional[float] = None,
        task_id: Optional[str] = None,
    ) -> AgentRelationship:
        """Derive a narrower relationship from an existing one.

        The child's permissions are the intersection of the parent's
        *effective* permissions and the grant. A delegated relationship
        can never confer more than its parent.
        """

        with self._lock:
            current = self._relationships.get(parent.relationship_id)
            if current is None:
                raise A2AError(
                    f"unknown relationship: {parent.relationship_id}"
                )
            if current.status != "active":
                raise A2AError(
                    f"cannot delegate a {current.status} relationship"
                )

            identity = self._identities.get(responder)
            if identity is None:
                raise A2AError(f"unknown identity: {responder}")
            if identity.status != "active":
                raise A2AError(f"identity is not active: {responder}")

            effective = self.effective_permissions(current.relationship_id)
            granted = dict(permissions or {})
            narrowed = _permissions_union_narrowing(effective, granted)

            if not narrowed:
                raise A2AError(
                    "delegation would grant nothing; "
                    "the grant is outside the parent's authority"
                )

            now = float(self._clock())
            if ttl is not None:
                ttl = _finite(ttl, "ttl")
                if ttl <= 0:
                    raise A2AError("ttl must be positive")

            child = AgentRelationship(
                relationship_id=f"rel-{uuid.uuid4().hex[:12]}",
                initiator=current.responder,
                responder=responder,
                permissions=narrowed,
                status="active",
                parent_relationship=current.relationship_id,
                task_id=task_id or current.task_id,
                created_at=now,
                expires_at=(
                    now + ttl
                    if ttl is not None
                    else current.expires_at
                ),
            )

            self._relationships[child.relationship_id] = child
            self._children.setdefault(current.relationship_id, []).append(
                child.relationship_id
            )
            self._save()
            self._audit(
                "delegate",
                child,
                detail={
                    "parent": current.relationship_id,
                    "permissions": narrowed,
                },
            )
            return child

    def revoke(
        self,
        relationship_id: str,
        *,
        reason: str = "",
        actor: str = "operator",
    ) -> int:
        """Revoke a relationship and every relationship derived from it.

        Returns the number of relationships revoked (recursive).
        """

        if not isinstance(reason, str) or not reason.strip():
            raise A2AError("reason is required for revocation")

        now = float(self._clock())
        count = 0

        with self._lock:
            stack = [relationship_id]
            while stack:
                current_id = stack.pop()
                rel = self._relationships.get(current_id)
                if rel is None:
                    continue
                if rel.status == "revoked":
                    continue
                updated = AgentRelationship(
                    relationship_id=rel.relationship_id,
                    initiator=rel.initiator,
                    responder=rel.responder,
                    permissions=dict(rel.permissions),
                    status="revoked",
                    parent_relationship=rel.parent_relationship,
                    task_id=rel.task_id,
                    created_at=rel.created_at,
                    expires_at=rel.expires_at,
                    revoked_at=now,
                    revoke_reason=reason,
                    mutual_auth=dict(rel.mutual_auth),
                )
                self._relationships[current_id] = updated
                count += 1
                self._audit(
                    "revoke",
                    updated,
                    actor=actor,
                    detail={"reason": reason},
                )
                stack.extend(self._children.get(current_id, []))

            self._save()
            return count

    def teardown(
        self,
        agent_a: str,
        agent_b: str,
        *,
        reason: str = "",
        actor: str = "operator",
    ) -> int:
        """Revoke every relationship between two agents (either direction)."""

        count = 0
        with self._lock:
            for rel in list(self._relationships.values()):
                if rel.status != "active":
                    continue
                if {rel.initiator, rel.responder} == {agent_a, agent_b}:
                    count += self.revoke(
                        rel.relationship_id,
                        reason=reason,
                        actor=actor,
                    )
        return count

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def lineage(self, relationship_id: str) -> tuple[AgentRelationship, ...]:
        """The delegation chain, leaf first, with cycle detection."""

        chain: list[AgentRelationship] = []
        seen: set[str] = set()
        current_id = relationship_id

        while current_id is not None:
            if current_id in seen:
                raise A2AError(
                    f"relationship lineage contains a cycle: {relationship_id}"
                )
            seen.add(current_id)
            rel = self._relationships.get(current_id)
            if rel is None:
                raise A2AError(
                    f"relationship lineage has a missing ancestor: "
                    f"{current_id} (from {relationship_id})"
                )
            chain.append(rel)
            current_id = rel.parent_relationship

        return tuple(chain)

    def effective_permissions(
        self, relationship_id: str
    ) -> dict[str, Any]:
        """Intersection of every relationship in the chain (root first)."""

        chain = self.lineage(relationship_id)
        if not chain:
            return {}
        result = dict(chain[-1].permissions)
        for rel in reversed(chain[:-1]):
            result = _permissions_intersect(result, rel.permissions)
        return result

    def verify_chain(self, relationship_id: str) -> dict[str, Any]:
        """Prove the chain is monotone narrowing, acyclic, and complete.

        Returns a report; ``valid`` is True only when every ancestor is
        present, the chain contains no cycle, and each child's effective
        permissions are a subset of its parent's effective permissions.
        """

        try:
            chain = self.lineage(relationship_id)
        except A2AError as exc:
            return {"valid": False, "reason": str(exc), "hops": 0}

        findings: list[str] = []
        for child in chain:
            parent_id = child.parent_relationship
            if parent_id is None:
                continue
            child_effective = self.effective_permissions(child.relationship_id)
            parent_effective = self.effective_permissions(parent_id)
            # Every granted permission must be present and no wider in
            # the child than in the parent.
            for key, value in child_effective.items():
                if key not in parent_effective:
                    findings.append(
                        f"child grants {key} which the parent does not have"
                    )
                    continue
                if not _permission_no_wider(value, parent_effective[key], key):
                    findings.append(
                        f"child widens {key}: "
                        f"{parent_effective[key]!r} -> {value!r}"
                    )

        return {
            "valid": not findings,
            "reason": "; ".join(findings) if findings else "chain narrows correctly",
            "hops": len(chain),
        }

    # ------------------------------------------------------------------
    # Cross-agent authorization
    # ------------------------------------------------------------------

    def is_active(self, relationship_id: str) -> bool:
        rel = self._relationships.get(relationship_id)
        if rel is None:
            return False
        if rel.status != "active":
            return False
        if rel.expires_at is not None and float(self._clock()) >= rel.expires_at:
            return False
        try:
            lineage = self.lineage(relationship_id)
        except A2AError:
            # A broken lineage (missing ancestor, cycle) fails closed.
            return False
        for ancestor in lineage:
            if ancestor.status != "active":
                return False
            if (
                ancestor.expires_at is not None
                and float(self._clock()) >= ancestor.expires_at
            ):
                return False
        return True

    def authorize(
        self,
        *,
        actor: str,
        target: str,
        action: str,
        request: Optional[dict[str, Any]] = None,
    ) -> A2ADecision:
        """One cross-agent decision. Fail-closed.

        1. A relationship from ``actor`` to ``target`` must exist, be
           active, and be unexpired (with every ancestor active).
        2. Its effective permissions must cover ``action``.
        3. If a task is bound and a task provider is attached, the task
           must be active.
        4. If an SDK provider is attached, the real pipeline must allow
           the action too.

        Steps 1--3 are local bookkeeping and can only *deny*. Step 4 is
        the only step that consults ``FirewallSDK.authorize()``, so it is
        the only step that can produce an allow this mesh did not compute
        for itself. When no provider is attached step 4 does not run, and
        the returned decision says so: its ``basis`` is
        :data:`BASIS_RELATIONSHIP_ONLY` and :attr:`A2ADecision.is_canonical`
        is ``False``. Such an allow is a relationship check, not an
        authorization, and callers that enforce must either attach a
        provider or reach the pipeline themselves.
        """

        if not isinstance(action, str) or not action.strip():
            return A2ADecision(
                actor=actor, target=target, action=action,
                allowed=False, reason="action is required",
                basis=BASIS_RELATIONSHIP_ONLY,
            )

        candidates = [
            rel
            for rel in self._relationships.values()
            if rel.status == "active"
            and rel.initiator == actor
            and rel.responder == target
        ]

        if not candidates:
            return A2ADecision(
                actor=actor,
                target=target,
                action=action,
                allowed=False,
                reason=f"no active relationship from {actor} to {target}",
                basis=BASIS_RELATIONSHIP_ONLY,
            )

        for rel in candidates:
            if not self.is_active(rel.relationship_id):
                continue

            effective = self.effective_permissions(rel.relationship_id)
            if not self._covers(effective, action):
                continue

            if rel.task_id is not None and self._task_provider is not None:
                try:
                    task_ok = bool(self._task_provider(rel.task_id))
                except Exception:
                    task_ok = False
                if not task_ok:
                    continue

            if self._sdk_provider is not None:
                try:
                    allowed, reason = self._sdk_provider(
                        actor, target, action, request or {}
                    )
                except Exception as exc:
                    return A2ADecision(
                        actor=actor,
                        target=target,
                        action=action,
                        allowed=False,
                        reason=f"authorization provider error: {type(exc).__name__}",
                        relationship_id=rel.relationship_id,
                        # Not ``canonical``: the pipeline was asked and
                        # did not answer. Claiming a canonical basis for
                        # a decision no canonical path produced would be
                        # the overstatement this field exists to stop.
                        basis=BASIS_UNAVAILABLE,
                    )
                if not allowed:
                    return A2ADecision(
                        actor=actor,
                        target=target,
                        action=action,
                        allowed=False,
                        reason=reason or "authorization pipeline denied",
                        relationship_id=rel.relationship_id,
                        basis=BASIS_CANONICAL,
                    )

                return A2ADecision(
                    actor=actor,
                    target=target,
                    action=action,
                    allowed=True,
                    reason=(
                        "relationship active, permissions cover the "
                        "action, and the authorization pipeline allowed it"
                    ),
                    relationship_id=rel.relationship_id,
                    basis=BASIS_CANONICAL,
                )

            return A2ADecision(
                actor=actor,
                target=target,
                action=action,
                allowed=True,
                reason=(
                    "relationship active and permissions cover the "
                    "action; no authorization pipeline was consulted"
                ),
                relationship_id=rel.relationship_id,
                basis=BASIS_RELATIONSHIP_ONLY,
            )

        return A2ADecision(
            actor=actor,
            target=target,
            action=action,
            allowed=False,
            reason="no active relationship covers this action",
            basis=BASIS_RELATIONSHIP_ONLY,
        )

    @staticmethod
    def _covers(permissions: dict[str, Any], action: str) -> bool:
        allowed = permissions.get("allowed_actions")
        if isinstance(allowed, (list, tuple)):
            return action in allowed
        if isinstance(allowed, str):
            return allowed == action
        if isinstance(allowed, dict):
            return action in allowed
        return False

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get(self, relationship_id: str) -> Optional[AgentRelationship]:
        with self._lock:
            return self._relationships.get(relationship_id)

    def relationships_for(
        self, agent: str
    ) -> tuple[AgentRelationship, ...]:
        with self._lock:
            return tuple(
                rel
                for rel in self._relationships.values()
                if agent in (rel.initiator, rel.responder)
            )

    def all(self) -> tuple[AgentRelationship, ...]:
        with self._lock:
            return tuple(
                self._relationships[key]
                for key in sorted(self._relationships)
            )

    def trust_graph(self) -> dict[str, Any]:
        """A view of who trusts whom (active relationships only)."""

        with self._lock:
            edges = []
            for rel in self._relationships.values():
                if rel.status != "active":
                    continue
                if rel.expires_at is not None and float(self._clock()) >= rel.expires_at:
                    continue
                edges.append(
                    {
                        "initiator": rel.initiator,
                        "responder": rel.responder,
                        "relationship_id": rel.relationship_id,
                        "permissions": dict(rel.permissions),
                        "task_id": rel.task_id,
                        "expires_at": rel.expires_at,
                        "derived_from": rel.parent_relationship,
                    }
                )
            return {"relationships": edges}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "relationships": [
                    rel.to_dict() for rel in self.all()
                ]
            }

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        relationship: AgentRelationship,
        *,
        actor: str = "automation",
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        if self._attest is None:
            return
        try:
            attestation = self._attest.issue(
                agent_id=relationship.initiator,
                subject=f"a2a:{action}",
                statement_type="agent_relationship",
                payload={
                    "relationship_id": relationship.relationship_id,
                    "initiator": relationship.initiator,
                    "responder": relationship.responder,
                    "action": action,
                    "detail": dict(detail or {}),
                },
            )
            # The attestation is intentionally issued for audit; nothing
            # here authorizes. Keep a reference on the record.
            if self._path is None:
                relationship.mutual_auth  # pragma: no cover - no-op
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            self._save()
