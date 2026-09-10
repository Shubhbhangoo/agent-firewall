"""Blast radius: bounded analysis of what a grant could reach.

§6 asks for a bounded notion of potential impact and requires the
distinction between analysis and authorization to be *structurally
obvious*. Four structural facts carry that here, none of them a naming
convention:

1. :class:`BlastRadius` has no field, property, or method that can be
   read as permission. There is no ``allowed``, no ``permit``, no
   ``score`` and no threshold. Adding one would be a visible API change,
   not a subtle drift.
2. ``bool(BlastRadius)`` raises. A blast radius cannot appear in an
   ``if`` at all, so ``if radius:`` is a crash rather than a policy.
3. The module imports nothing from ``firewall.sdk`` and never constructs
   an :class:`~firewall.authorization.AuthorizationResult`. That is
   machine-checked, not merely intended: ``AUTHORIZATION_RESULT_OWNERS``
   restricts result construction to ``firewall/authorization.py`` and
   ``firewall/sdk.py``, and AUTHORIZATION_UNIQUENESS fails if a third
   file ever constructs one.
4. Every finding is basis-tagged ``derived``, never ``observed``.
   Reachability is computed from recorded structure, so it is a
   derivation about the estate and not an observation of the world.

Boundedness is the other half of §6, and it is enforced rather than
assumed. Traversal is breadth-first with an explicit frontier cap, node
cap, and depth cap. When a cap is reached the traversal stops and records
an :class:`Unanalyzable` entry naming which cap and where, and
``complete`` becomes ``False``. There is no configuration in which the
traversal is unbounded, so a pathological delegation forest costs a fixed
amount of work rather than an unbounded amount (§10's graph explosion and
DoS-through-pathological-state cases).

What incompleteness means
-------------------------

An incomplete blast radius is **larger** than what was computed, never
smaller: truncation drops descendants, and a dropped descendant is
reachable impact that was not counted. So a caller may never read a small
``reach`` from an incomplete analysis as "bounded impact" -- and
:func:`impact_of` will not let it, because incompleteness resolves to
``UNANALYZABLE`` rather than to a size class. That is the same rule as
``UNKNOWN`` never becoming ``SAFE``, applied one layer down.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

#: Traversal caps. Deliberately module-level constants rather than
#: parameters without defaults: every construction is bounded, and a
#: caller that wants different bounds passes smaller ones.
MAX_NODES = 2048
MAX_DEPTH = 64
MAX_FRONTIER = 4096


@dataclass(frozen=True)
class Unanalyzable:
    """Something the analysis could not establish, and why.

    Carried in the result rather than raised, because a raise would let a
    caller wrap the analysis in ``try``/``except`` and continue as though
    the estate were small.
    """

    kind: str
    detail: str
    at: Optional[str] = None

    def describe(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "at": self.at}


@dataclass(frozen=True)
class BlastRadius:
    """What a grant could reach if it were fully used or fully misused.

    ``derived`` throughout. Not a decision, and not usable as one.
    """

    #: The grant this radius was computed for.
    fingerprint: str
    #: Descendant grants in the delegation lineage, nearest first.
    descendants: tuple[str, ...] = ()
    #: Capability names those grants carry, where known.
    capabilities: tuple[str, ...] = ()
    #: Agents that hold a grant in the subtree.
    agents: tuple[str, ...] = ()
    #: Tools and resources, when an attack graph was supplied.
    tools: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    #: Reachable labels the existing attack graph flags as sensitive.
    sensitive_targets: tuple[str, ...] = ()
    #: Deepest lineage level reached, 0 when the grant has no children.
    depth: int = 0
    #: Everything the traversal could not establish.
    unanalyzable: tuple[Unanalyzable, ...] = ()
    #: Always ``derived``.
    basis: str = "derived"
    details: Mapping[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        raise TypeError(
            "a BlastRadius is not a decision; it is derived analysis. Read "
            ".reach or .complete, and call FirewallSDK.authorize() to decide"
        )

    @property
    def complete(self) -> bool:
        """Did the traversal finish without hitting a cap or a gap?"""

        return not self.unanalyzable

    @property
    def reach(self) -> int:
        """How many distinct things the subtree touches.

        A count, not a score: it is not compared against a threshold
        anywhere in the codebase, and :func:`impact_of` uses it only to
        pick a label that no gate reads.
        """

        return len(
            set(self.descendants)
            | set(self.capabilities)
            | set(self.agents)
            | set(self.tools)
            | set(self.resources)
        )

    @property
    def touches_sensitive(self) -> bool:
        return bool(self.sensitive_targets)

    def describe(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "descendants": list(self.descendants),
            "capabilities": list(self.capabilities),
            "agents": list(self.agents),
            "tools": list(self.tools),
            "resources": list(self.resources),
            "sensitive_targets": list(self.sensitive_targets),
            "depth": self.depth,
            "reach": self.reach,
            "complete": self.complete,
            "touches_sensitive": self.touches_sensitive,
            "unanalyzable": [item.describe() for item in self.unanalyzable],
            "basis": self.basis,
            "details": dict(self.details),
        }
def _children_index(
    edges: Iterable[Any],
) -> tuple[dict[str, list[str]], tuple[Unanalyzable, ...]]:
    """Parent -> children, from ``DelegationLineage.snapshot()`` records.

    Accepts either the ``LineageRecord`` dataclass or a
    ``(child, parent)`` pair, so a caller can pass a lineage snapshot or
    a plain edge list without Aegis reaching into lineage internals.
    """

    index: dict[str, list[str]] = {}
    findings: list[Unanalyzable] = []
    seen = 0

    for edge in edges:
        seen += 1

        if seen > MAX_FRONTIER:
            findings.append(
                Unanalyzable(
                    kind="edge_cap",
                    detail=(
                        f"lineage has more than {MAX_FRONTIER} edges; the "
                        f"subtree index is partial and the true radius is "
                        f"larger than what was computed"
                    ),
                )
            )
            break

        child = getattr(edge, "child_fingerprint", None)
        parent = getattr(edge, "parent_fingerprint", None)

        if child is None or parent is None:
            try:
                child, parent = edge
            except (TypeError, ValueError):
                findings.append(
                    Unanalyzable(
                        kind="malformed_edge",
                        detail=f"lineage edge is not readable: {type(edge).__name__}",
                    )
                )
                continue

        if not isinstance(child, str) or not isinstance(parent, str):
            findings.append(
                Unanalyzable(
                    kind="malformed_edge",
                    detail="lineage edge does not name two fingerprints",
                )
            )
            continue

        index.setdefault(parent, []).append(child)

    for children in index.values():
        children.sort()

    return index, tuple(findings)


def _graph_reach(
    graph: Any,
    agents: Iterable[str],
) -> tuple[dict[str, set[str]], tuple[Unanalyzable, ...]]:
    """Fold ``AttackGraph.blast_radius`` over the agents in the subtree.

    Composes the existing engine rather than re-walking the graph. A
    graph that raises, or answers with something unreadable, produces an
    :class:`Unanalyzable` entry -- the analysis records that it is blind
    rather than reporting a small radius.
    """

    collected: dict[str, set[str]] = {
        "capabilities": set(),
        "tools": set(),
        "resources": set(),
        "sensitive_targets": set(),
    }
    findings: list[Unanalyzable] = []

    if graph is None:
        return collected, ()

    reader = None

    try:
        reader = getattr(graph, "blast_radius", None)
    except Exception as error:  # noqa: BLE001 - recorded, never raised
        # Reading the *attribute* can fail: a lazily-resolving or remote
        # graph proxy raises from ``__getattr__``. This module promises it
        # never raises, and the promise has to cover the lookup as well as
        # the call.
        return collected, (
            Unanalyzable(
                kind="graph_error",
                detail=f"{type(error).__name__} looking up blast_radius",
            ),
        )

    if not callable(reader):
        return collected, (
            Unanalyzable(
                kind="graph_unreadable",
                detail="the supplied graph has no callable blast_radius",
            ),
        )

    for agent in sorted(set(agents)):
        try:
            answer = reader(agent)
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            findings.append(
                Unanalyzable(
                    kind="graph_error",
                    detail=f"{type(error).__name__} reading the graph",
                    at=agent,
                )
            )
            continue

        if not isinstance(answer, Mapping):
            findings.append(
                Unanalyzable(
                    kind="graph_unreadable",
                    detail="blast_radius did not return a mapping",
                    at=agent,
                )
            )
            continue

        for key in collected:
            values = answer.get(key, ())

            if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
                findings.append(
                    Unanalyzable(
                        kind="graph_unreadable",
                        detail=f"blast_radius {key!r} is not a sequence",
                        at=agent,
                    )
                )
                continue

            for value in values:
                if isinstance(value, str):
                    collected[key].add(value)

    return collected, tuple(findings)
def blast_radius(
    fingerprint: str,
    *,
    lineage_edges: Iterable[Any] = (),
    grants: Optional[Mapping[str, Any]] = None,
    graph: Any = None,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> BlastRadius:
    """Compute the bounded blast radius of ``fingerprint``.

    ``grants`` maps fingerprint to anything carrying ``agent_id`` and
    ``capability`` attributes -- an :class:`~firewall.aegis.state.AegisGrant`
    or a :class:`~firewall.capability.Capability` both work. A descendant
    missing from ``grants`` is recorded as unanalyzable rather than
    silently skipped: an unnamed descendant is still reachable impact.

    Never raises. A traversal that cannot complete says so.
    """

    if not isinstance(fingerprint, str) or not fingerprint:
        return BlastRadius(
            fingerprint="",
            unanalyzable=(
                Unanalyzable(
                    kind="no_subject",
                    detail="blast radius requires a fingerprint to start from",
                ),
            ),
        )

    max_nodes = max(1, min(int(max_nodes), MAX_NODES))
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))

    index, findings = _children_index(lineage_edges)
    unanalyzable: list[Unanalyzable] = list(findings)

    descendants: list[str] = []
    capabilities: set[str] = set()
    agents: set[str] = set()
    visited: set[str] = {fingerprint}
    depth_reached = 0

    frontier: deque[tuple[str, int]] = deque([(fingerprint, 0)])

    while frontier:
        current, depth = frontier.popleft()

        if depth >= max_depth:
            unanalyzable.append(
                Unanalyzable(
                    kind="depth_cap",
                    detail=(
                        f"stopped at depth {max_depth}; descendants below this "
                        f"point are not counted, so the true radius is larger"
                    ),
                    at=current,
                )
            )
            continue

        for child in index.get(current, ()):
            if child in visited:
                # A cycle in recorded lineage. ``DelegationLineage``
                # refuses to register one, so reaching here means the
                # edges came from somewhere else; either way the
                # traversal terminates and the anomaly is reported.
                unanalyzable.append(
                    Unanalyzable(
                        kind="lineage_cycle",
                        detail=f"{current} -> {child} revisits a seen grant",
                        at=child,
                    )
                )
                continue

            if len(visited) >= max_nodes:
                unanalyzable.append(
                    Unanalyzable(
                        kind="node_cap",
                        detail=(
                            f"stopped after {max_nodes} grants; the true "
                            f"radius is larger than what was computed"
                        ),
                        at=child,
                    )
                )
                frontier.clear()
                break

            visited.add(child)
            descendants.append(child)
            depth_reached = max(depth_reached, depth + 1)
            frontier.append((child, depth + 1))

    subject = None if grants is None else grants.get(fingerprint)

    for name in [fingerprint] + descendants:
        record = None if grants is None else grants.get(name)

        if record is None:
            if grants is not None:
                unanalyzable.append(
                    Unanalyzable(
                        kind="unknown_grant",
                        detail=(
                            "a grant in the subtree is not registered, so its "
                            "capability and holder could not be read"
                        ),
                        at=name,
                    )
                )
            continue

        capability = getattr(record, "capability", None)
        agent = getattr(record, "agent_id", None)

        if isinstance(capability, str) and capability:
            capabilities.add(capability)

        if isinstance(agent, str) and agent:
            agents.add(agent)

    graph_reach, graph_findings = _graph_reach(graph, agents)
    unanalyzable.extend(graph_findings)
    capabilities |= graph_reach["capabilities"]

    return BlastRadius(
        fingerprint=fingerprint,
        descendants=tuple(descendants),
        capabilities=tuple(sorted(capabilities)),
        agents=tuple(sorted(agents)),
        tools=tuple(sorted(graph_reach["tools"])),
        resources=tuple(sorted(graph_reach["resources"])),
        sensitive_targets=tuple(sorted(graph_reach["sensitive_targets"])),
        depth=depth_reached,
        unanalyzable=tuple(unanalyzable),
        details={
            "subject_registered": subject is not None,
            "lineage_edges_indexed": sum(
                len(children) for children in index.values()
            ),
            "graph_consulted": graph is not None,
            "max_nodes": max_nodes,
            "max_depth": max_depth,
        },
    )
