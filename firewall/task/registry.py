"""v2.0 Task-Bound Authority (firewall.task).

Authorization scoped by task: an agent acts under a *task* that carries
its own identity, lifecycle, and permissions, and delegation runs
through task chains.

Key guarantees:

* **Delegation never increases authority.** A child task's permissions
  are the intersection of the parent's effective permissions and the
  delegated grant. A grandchild cannot obtain more than the legitimate
  chain grants it.
* **Task identity is bound to the agent identity** that created it.
* **Expiration** is enforced by the task registry at authorization
  time (``is_active``).
* **Revocation** of a task or any ancestor revokes the whole subtree
  (``is_revoked`` walks the parent chain).
* The task layer never authorizes anything itself: it only answers
  *which permissions are active*; the authorization pipeline decides.

The model:

    agent A creates task T1 (permissions P1)
      - delegates T1 -> task T2 for agent B (grant G2)
          effective(T2) = P1 intersect G2
      - delegates T2 -> task T3 for agent C (grant G3)
          effective(T3) = effective(T2) intersect G3
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

#: Current task record format version.
TASK_VERSION = 1


class TaskError(ValueError):
    """Raised for an invalid task operation."""


def _permissions_intersect(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    """Intersection of two permission maps.

    Keys present in both must agree in value (a string match, a number
    ceiling, or a list membership narrowing). Any key absent from either
    side is dropped -- authority only shrinks.
    """

    out: dict[str, Any] = {}

    for key, left_value in left.items():
        if key not in right:
            continue

        right_value = right[key]

        if isinstance(left_value, (int, float)) and isinstance(
            right_value, (int, float)
        ):
            if isinstance(left_value, bool) or isinstance(
                right_value, bool
            ):
                if left_value == right_value:
                    out[key] = left_value
                continue
            # Numeric constraints narrow to the tighter bound.
            out[key] = min(left_value, right_value)
            continue

        if isinstance(left_value, (list, tuple)) and isinstance(
            right_value, (list, tuple)
        ):
            shared = [item for item in left_value if item in right_value]
            out[key] = shared
            continue

        if left_value == right_value:
            out[key] = left_value

    return out


@dataclass(frozen=True)
class Task:
    """One task with its permissions and lifecycle."""

    task_id: str
    agent_id: str
    permissions: dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    parent_task: Optional[str] = None
    created_at: float = 0.0
    expires_at: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id.strip():
            raise TaskError("task_id is required")
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise TaskError("agent_id is required")
        if self.status not in ("active", "completed", "revoked", "expired"):
            raise TaskError(f"unknown task status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "permissions": dict(self.permissions),
            "status": self.status,
            "parent_task": self.parent_task,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Task":
        if not isinstance(payload, dict):
            raise TaskError("task must be an object")
        return cls(
            task_id=payload.get("task_id"),
            agent_id=payload.get("agent_id"),
            permissions=dict(payload.get("permissions", {}) or {}),
            status=payload.get("status", "active"),
            parent_task=payload.get("parent_task"),
            created_at=float(payload.get("created_at", 0.0)),
            expires_at=(
                float(payload["expires_at"])
                if payload.get("expires_at") is not None
                else None
            ),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


class TaskRegistry:
    """Persistent task registry with delegation chains."""

    def __init__(
        self,
        *,
        state_path: Optional[str | Path] = None,
        clock: Any = None,
        identity_registry=None,
    ) -> None:
        self._lock = threading.RLock()
        self._path = Path(state_path) if state_path else None
        self._clock = clock if clock is not None else time.time
        self._identities = identity_registry
        self._tasks: dict[str, Task] = {}

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
            raise TaskError(f"cannot load task state: {exc}") from exc

        for entry in data.get("tasks", []):
            try:
                task = Task.from_dict(entry)
            except TaskError:
                continue
            self._tasks[task.task_id] = task

    def _save(self) -> None:
        if self._path is None:
            return

        import os
        import tempfile

        data = {
            "tasks": [
                task.to_dict() for task in self._tasks.values()
            ]
        }

        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".task-state.",
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

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create(
        self,
        *,
        agent_id: str,
        permissions: Optional[dict[str, Any]] = None,
        expires_at: Optional[float] = None,
        metadata: Optional[dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Task:
        """Create a root task for ``agent_id``."""

        if not isinstance(agent_id, str) or not agent_id.strip():
            raise TaskError("agent_id is required")

        if self._identities is not None:
            if self._identities.get(agent_id) is None:
                raise TaskError(
                    f"unknown identity: {agent_id}"
                )

        if (
            expires_at is not None
            and float(expires_at) <= float(self._clock())
        ):
            raise TaskError("expires_at must be in the future")

        with self._lock:
            task = Task(
                task_id=(
                    task_id
                    if task_id is not None
                    else f"task-{uuid.uuid4().hex[:12]}"
                ),
                agent_id=agent_id,
                permissions=dict(permissions or {}),
                status="active",
                parent_task=None,
                created_at=float(self._clock()),
                expires_at=(
                    float(expires_at)
                    if expires_at is not None
                    else None
                ),
                metadata=dict(metadata or {}),
            )

            if task.task_id in self._tasks:
                raise TaskError(
                    f"task already exists: {task.task_id}"
                )

            self._tasks[task.task_id] = task
            self._save()
            return task

    def delegate(
        self,
        parent_task: Task,
        *,
        agent_id: str,
        permissions: Optional[dict[str, Any]] = None,
        expires_at: Optional[float] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Task:
        """Delegate a task to another agent.

        The child's effective permissions are the intersection of the
        parent's effective permissions and the grant. Delegation can
        only narrow.
        """

        with self._lock:
            current = self._tasks.get(parent_task.task_id)

            if current is None:
                raise TaskError(
                    f"unknown task: {parent_task.task_id}"
                )

            if current.status in ("revoked", "expired", "completed"):
                raise TaskError(
                    f"cannot delegate a {current.status} task"
                )

            if self._identities is not None:
                if self._identities.get(agent_id) is None:
                    raise TaskError(
                        f"unknown identity: {agent_id}"
                    )

            effective = self.effective_permissions(
                current.task_id
            )

            granted = dict(permissions or {})

            narrowed = _permissions_intersect(
                effective,
                granted,
            )

            child = Task(
                task_id=f"task-{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                permissions=narrowed,
                status="active",
                parent_task=current.task_id,
                created_at=float(self._clock()),
                expires_at=(
                    float(expires_at)
                    if expires_at is not None
                    else current.expires_at
                ),
                metadata=dict(metadata or {}),
            )

            self._tasks[child.task_id] = child
            self._save()
            return child

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def get(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def require(self, task_id: str) -> Task:
        task = self.get(task_id)
        if task is None:
            raise TaskError(f"unknown task: {task_id}")
        return task

    def tasks_for_agent(
        self,
        agent_id: str,
    ) -> tuple[Task, ...]:
        with self._lock:
            return tuple(
                task
                for task in self._tasks.values()
                if task.agent_id == agent_id
            )

    def all(self) -> tuple[Task, ...]:
        with self._lock:
            return tuple(self._tasks.values())

    # ------------------------------------------------------------------
    # Delegation chain resolution
    # ------------------------------------------------------------------

    def lineage(self, task_id: str) -> tuple[Task, ...]:
        """The task chain, leaf first: child -> parent -> ... -> root."""

        chain: list[Task] = []
        seen: set[str] = set()
        current_id = task_id

        while current_id is not None:
            if current_id in seen:
                raise TaskError(
                    f"task lineage contains a cycle: {task_id}"
                )
            seen.add(current_id)

            task = self._tasks.get(current_id)
            if task is None:
                raise TaskError(
                    f"task lineage has a missing ancestor: "
                    f"{current_id} (from {task_id})"
                )

            chain.append(task)
            current_id = task.parent_task

        return tuple(chain)

    def effective_permissions(
        self,
        task_id: str,
    ) -> dict[str, Any]:
        """The intersection of every task in the chain.

        The root's permissions narrow through each delegation. This is
        the *maximum* authority the task can ever confer.
        """

        chain = self.lineage(task_id)

        if not chain:
            return {}

        result = dict(chain[-1].permissions)  # root first

        for task in reversed(chain[:-1]):
            result = _permissions_intersect(
                result,
                task.permissions,
            )

        return result

    # ------------------------------------------------------------------
    # Lifecycle / checks
    # ------------------------------------------------------------------

    def is_active(self, task_id: str) -> bool:
        task = self.get(task_id)
        if task is None:
            return False

        if task.status != "active":
            return False

        if task.expires_at is not None:
            if float(self._clock()) >= task.expires_at:
                return False

        # Any revoked/expired/completed ancestor revokes the subtree.
        for ancestor in self.lineage(task_id):
            if ancestor.status != "active":
                return False
            if ancestor.expires_at is not None:
                if float(self._clock()) >= ancestor.expires_at:
                    return False

        return True

    def check(
        self,
        task_id: str,
        action: str,
    ) -> bool:
        """Does the task's effective permissions cover ``action``?

        A helper for callers that keep permissions as an action map.
        Returns ``False`` when the task is not active -- an inactive
        task grants nothing.
        """

        if not self.is_active(task_id):
            return False

        permissions = self.effective_permissions(task_id)

        allowed = permissions.get("allowed_actions")

        if isinstance(allowed, (list, tuple)):
            return action in allowed

        if isinstance(allowed, str):
            return allowed == action

        return False

    def complete(self, task_id: str) -> Task:
        with self._lock:
            task = self.require(task_id)
            updated = Task(
                task_id=task.task_id,
                agent_id=task.agent_id,
                permissions=dict(task.permissions),
                status="completed",
                parent_task=task.parent_task,
                created_at=task.created_at,
                expires_at=task.expires_at,
                metadata=dict(task.metadata),
            )
            self._tasks[task_id] = updated
            self._save()
            return updated

    def revoke(self, task_id: str, *, reason: str = "") -> Task:
        with self._lock:
            task = self.require(task_id)
            metadata = dict(task.metadata)
            metadata["revoked_at"] = float(self._clock())
            if reason:
                metadata["revoke_reason"] = reason

            updated = Task(
                task_id=task.task_id,
                agent_id=task.agent_id,
                permissions=dict(task.permissions),
                status="revoked",
                parent_task=task.parent_task,
                created_at=task.created_at,
                expires_at=task.expires_at,
                metadata=metadata,
            )

            self._tasks[task_id] = updated
            self._save()
            return updated

    def is_revoked(self, task_id: str) -> bool:
        try:
            return any(
                ancestor.status == "revoked"
                for ancestor in self.lineage(task_id)
            )
        except TaskError:
            return True  # fail closed on broken lineage

    def close(self) -> None:
        with self._lock:
            self._save()
