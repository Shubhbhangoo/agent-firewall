"""Task-Bound Authority (v2.0).

Authorization scoped by task: an agent acts under a task that carries
its own permissions and lifecycle, and delegation runs through task
chains that can only narrow authority. The task layer answers *which
permissions are active*; the authorization pipeline decides.
"""

from firewall.task.registry import (
    TASK_VERSION,
    Task,
    TaskError,
    TaskRegistry,
    _permissions_intersect,
)

__all__ = [
    "TASK_VERSION",
    "Task",
    "TaskError",
    "TaskRegistry",
    "_permissions_intersect",
]
