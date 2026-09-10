"""Security timeline, trajectory, and relationship graph (v1.8).

Three read-only projections over a recorded artifact:

* :mod:`firewall.timeline.timeline` -- the chronological security story,
  every entry bound to the event that produced it.
* :mod:`firewall.timeline.trajectory` -- evidence-backed posture
  transitions (``trusted -> unusual -> suspicious -> high_risk ->
  contained -> recovered``).
* :mod:`firewall.timeline.graph` -- derived nodes and edges answering
  "why could this agent do this?" and "what could it reach?".

All three derive from recorded events only; none of them authorize
anything.
"""

from firewall.timeline.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
)
from firewall.timeline.timeline import (
    TimelineEntry,
    build_timeline,
    summarize_event,
    timeline_to_text,
)
from firewall.timeline.trajectory import (
    Posture,
    PostureTransition,
    Trajectory,
    from_artifact as trajectory_from_artifact,
    from_events as trajectory_from_events,
    trajectory_to_text,
)

__all__ = [
    "EdgeType",
    "GraphEdge",
    "GraphNode",
    "NodeType",
    "Posture",
    "PostureTransition",
    "SecurityGraph",
    "TimelineEntry",
    "Trajectory",
    "build_timeline",
    "summarize_event",
    "timeline_to_text",
    "trajectory_from_artifact",
    "trajectory_from_events",
    "trajectory_to_text",
]
