"""v2.2 adversarial weakness search over the security twin.

:class:`firewall.twin.SecurityTwin` answers "what happens if ...". This
module asks the complementary question -- "what is already wrong?" -- by
searching the recorded security graph for weaknesses:

* privilege escalation to sensitive resources
* transitive trust that creates reach no direct relationship grants
* the blast radius of a compromised agent
* lateral movement between agents
* multi-agent delegation chains
* revocations the reachability analysis does not honour
* weak-basis edges whose promotion would widen recorded reach
* confused-deputy exposure

Every search snapshots the live graph and reads only the copy, is bounded
by a node ceiling and a deadline that it reports honestly, and is
deterministic under a pinned clock. Nothing here authorizes anything:
``FirewallSDK.authorize`` neither imports nor consults this module, and a
weakness finding is evidence for a human or a policy author -- never a
grant, and never a denial.

A finding's ``basis`` is never ``observed``. A search reports a
conclusion drawn from recorded edges, and a conclusion is derived at
best; where the edges it rests on are weaker than that, the finding
inherits the weaker basis. Inference is not observation.

Four candidate searches were removed rather than kept, because none could
establish what it claimed:

*Policy conflicts.* It reported any two policy nodes with an overlapping
agent set. The attack graph records that a policy applies to an agent,
not what the policy decides, so overlap is all it can see -- and overlap
is ordinary. Conflict analysis needs rule semantics and belongs to
:mod:`firewall.policy_analysis`, which works over recorded decisions.

*Revocation bypass.* It reported every ``derived_from`` edge without a
``revoked`` attribute as "missing revocation check": a finding that fires
on healthy state, describing a check that does not live in this graph at
all. Revocation is enforced by ``FirewallSDK.authorize``'s revocation
gate. :meth:`AdversarialDigitalTwin.search_unenforced_revocation`
replaces it with the one revocation weakness a graph search can
establish.

*Dangerous capability combinations.* A wrapper around
:meth:`AttackGraph.capability_combinations`, which reports capability
pairs whose union reaches a sensitive resource that neither reaches
alone. The graph records no conjunctive prerequisite -- no edge saying a
path needs two capabilities at once -- so reach is additive: the union's
reach is the union of the reaches, and a sensitive resource in the union
is in at least one of them. The condition is unsatisfiable by
construction, and the analysis returns an empty list for every graph.
Reporting it as a search would document a detection that cannot happen.

*Delegation abuse.* A wrapper around
:meth:`AttackGraph.delegation_abuse`, which reports a ``delegates`` edge
whose grantee's *reach* contains a capability the grantor's reach does
not. :meth:`AttackGraph.reachable` follows the delegation edge, so the
grantor's reach always contains the grantee's: the difference is empty
for every graph. The condition is expressible over what each agent
*holds* rather than reaches -- but in this graph that is the same shape
as :meth:`AdversarialDigitalTwin.search_confused_deputy`, and one
security concept gets one representation. Delegation widening is
enforced, not merely reported, by ``FirewallSDK.authorize``'s
delegation-monotonicity check.

Both dead analyses remain in :mod:`firewall.attackgraph` untouched: they
return an empty list, which is not an unsafe answer, and v2.1 behavior is
not changed on the strength of a v2.2 observation. What changed there is
one honesty correction: ``trust_transitivity`` described "reach over
sensitive resources" while testing for reach over *any* resource, through
a dead conditional expression. It now tests ``is_sensitive`` and names the
resources it found, so the finding says what was established. The change
only narrows what is reported.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Optional

from firewall.attackgraph import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
    is_sensitive,
)
from firewall.network import AgentNetworkGraph
from firewall.twin.twin import TwinError, _clone

#: Hop ceiling for path searches.
MAX_SEARCH_DEPTH = 10

#: Node ceiling for one search.
MAX_SEARCH_NODES = 1000

#: Path ceiling per target.
MAX_PATHS_PER_TARGET = 50

#: Wall-clock ceiling for one search, in seconds.
SEARCH_TIMEOUT_SECONDS = 30.0

#: Severities a weakness may carry, weakest first. ``critical`` is
#: emitted by one search only -- an unenforced revocation whose
#: capability is still reachable. Reachability is not exploitation, so no
#: reach finding claims the top level.
WEAKNESS_SEVERITIES = ("low", "medium", "high", "critical")

#: Every search, by name. Each name has a ``search_<name>`` method.
SEARCH_TYPES = (
    "privilege_escalation",
    "trust_transitivity",
    "compromised_agent_impact",
    "lateral_movement",
    "multi_agent_attack_chains",
    "unenforced_revocation",
    "promotable_provenance",
    "confused_deputy",
)

_BASIS_RANK = {
    "unknown": 0,
    "simulated": 1,
    "inferred": 2,
    "derived": 3,
    "observed": 4,
}

#: Severity of a reach finding, by the basis of the path showing it.
_REACH_SEVERITY = {
    "observed": "high",
    "derived": "medium",
    "inferred": "low",
    "simulated": "low",
    "unknown": "low",
}


def _capped(basis: str) -> str:
    """The basis a conclusion resting on ``basis`` may claim.

    Capped at ``derived``: a search reports what follows from recorded
    edges, never a fresh observation. An unrecognized basis reads
    ``unknown`` -- unknown is not trusted.
    """

    if basis not in _BASIS_RANK:
        return "unknown"
    if _BASIS_RANK[basis] > _BASIS_RANK["derived"]:
        return "derived"
    return basis


def _label(graph: AttackGraph, node_id: str) -> str:
    node = graph.node(node_id)
    return node.label if node is not None else node_id


def _agent_label(graph: AttackGraph, node_id: str) -> Optional[str]:
    """``node_id``'s label if it is an agent, else ``None``.

    The first draft fell back to ``"unknown"`` here, which put findings
    naming a nonexistent agent into the record.
    """

    node = graph.node(node_id)
    if node is None or node.type != "agent":
        return None
    return node.label


def _sensitive_resources(graph: AttackGraph) -> tuple[AttackNode, ...]:
    """Sensitive resource nodes, in the graph's own insertion order."""

    return tuple(
        node
        for node in graph.nodes()
        if node.type == "resource" and is_sensitive(node.label)
    )


def _reaching(graph: AttackGraph, capability: str) -> tuple[str, ...]:
    """Agents whose recorded reach still includes ``capability``."""

    holders: set[str] = set()
    for agent_id in graph.agent_ids():
        reach = graph.reachable(agent_id)
        if capability in reach["capabilities"]:
            holders.add(_label(graph, agent_id))
    return tuple(sorted(holders))


@dataclass(frozen=True)
class WeaknessFinding:
    """One weakness the adversarial search established.

    ``basis`` records what the finding rests on and is validated: a
    search may not label its own conclusion ``observed``.

    The first draft carried a ``confidence`` float. It is gone: every
    value was a literal chosen at the call site (0.7, 0.5, 0.4, 0.3) with
    nothing behind it, and a number invites arithmetic its provenance
    cannot support. ``severity`` ranks findings; ``basis`` says how well
    each is founded.
    """

    weakness_type: str
    description: str
    severity: str
    basis: str = "derived"
    agents_involved: tuple[str, ...] = ()
    attack_path: Optional[AttackPath] = None
    evidence: tuple[dict[str, Any], ...] = ()
    remediation: str = ""

    def __post_init__(self) -> None:
        if not str(self.weakness_type).strip():
            raise TwinError("weakness_type must be a non-empty string")
        if self.severity not in WEAKNESS_SEVERITIES:
            raise TwinError(f"unknown severity: {self.severity}")
        if self.basis not in _BASIS_RANK:
            raise TwinError(f"unknown basis: {self.basis}")
        if self.basis == "observed":
            raise TwinError(
                "a search result is a conclusion, never an observation"
            )
        if not isinstance(self.evidence, tuple):
            raise TwinError("evidence must be a tuple of dicts")
        if not isinstance(self.agents_involved, tuple):
            raise TwinError("agents_involved must be a tuple of labels")

    def to_dict(self) -> dict[str, Any]:
        return {
            "weakness_type": self.weakness_type,
            "description": self.description,
            "severity": self.severity,
            "basis": self.basis,
            "agents_involved": list(self.agents_involved),
            "attack_path": (
                self.attack_path.to_dict()
                if self.attack_path is not None
                else None
            ),
            "evidence": [dict(entry) for entry in self.evidence],
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class TwinSearchResult:
    """The outcome of one search, including how it ended.

    ``terminated_early`` and ``termination_reason`` are validated against
    each other. A search that stopped at a bound and did not say so would
    report a partial answer as a complete one -- silence about a bound
    reads as "nothing found".
    """

    search_type: str
    target: str
    findings: tuple[WeaknessFinding, ...] = ()
    search_space_explored: int = 0
    search_time: float = 0.0
    terminated_early: bool = False
    termination_reason: str = ""

    def __post_init__(self) -> None:
        if self.terminated_early and not self.termination_reason:
            raise TwinError("an early termination must name its reason")
        if self.termination_reason and not self.terminated_early:
            raise TwinError(
                "a termination reason means the search ended early"
            )
        if not isinstance(self.findings, tuple):
            raise TwinError("findings must be a tuple")

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_type": self.search_type,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "search_space_explored": self.search_space_explored,
            "search_time": self.search_time,
            "terminated_early": self.terminated_early,
            "termination_reason": self.termination_reason,
        }


class _Budget:
    """The bound every search runs under.

    Two limits, checked by the search as it explores: a node ceiling and
    a deadline. Whichever is hit first stops the search and names itself,
    so termination is guaranteed and reported rather than assumed.

    The deadline is read from the twin's clock. A pinned clock therefore
    makes a search deterministic instead of machine-dependent.
    """

    __slots__ = ("_clock", "_max_nodes", "_start", "_deadline", "spent",
                 "reason")

    def __init__(
        self,
        clock: Callable[[], float],
        *,
        max_nodes: int,
        timeout: float,
    ) -> None:
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int):
            raise TwinError("max_nodes must be an integer")
        if max_nodes <= 0:
            raise TwinError("max_nodes must be positive")
        if isinstance(timeout, bool) or not isinstance(
            timeout, (int, float)
        ):
            raise TwinError("timeout must be a number")
        if timeout <= 0:
            raise TwinError("timeout must be positive")

        self._clock = clock
        self._max_nodes = int(max_nodes)
        self._start = float(clock())
        self._deadline = self._start + float(timeout)
        self.spent = 0
        self.reason = ""

    def spend(self, nodes: int = 1) -> bool:
        """Charge ``nodes`` and report whether the search may continue."""

        self.spent += max(0, int(nodes))
        if self.spent > self._max_nodes:
            self.reason = "node_limit"
            return False
        if float(self._clock()) >= self._deadline:
            self.reason = "timeout"
            return False
        return True

    @property
    def exhausted(self) -> bool:
        return bool(self.reason)

    def elapsed(self) -> float:
        return float(self._clock()) - self._start


def _route(path: AttackPath) -> str:
    """The path as labels and edge types, ``a -[trusts]-> b``.

    Two distinct paths between the same pair of nodes otherwise produce
    two identical descriptions, which reads as one finding reported twice.
    The edge type is part of the route because two agents can be joined by
    both a trust edge and a delegation.
    """

    if not path.hops:
        return ""
    parts = [path.hops[0]["from_label"]]
    for hop in path.hops:
        parts.append(f"-[{hop['edge']}]->")
        parts.append(hop["to_label"])
    return " ".join(parts)


def _reach_finding(
    weakness_type: str,
    agents: tuple[str, ...],
    path: AttackPath,
    target: str,
    *,
    remediation: str,
    description: Optional[str] = None,
) -> WeaknessFinding:
    """A finding whose whole content is "this reach exists".

    Shared by the three searches that report a path, so that one path
    means one severity rule: the weakest hop on the path decides, because
    a chain of authority is no better founded than its weakest link.
    """

    return WeaknessFinding(
        weakness_type=weakness_type,
        description=description or (
            f"{agents[0]} reaches {target} in {len(path.hops)} hop(s)"
        ),
        severity=_REACH_SEVERITY.get(path.basis, "low"),
        basis=_capped(path.basis),
        agents_involved=agents,
        attack_path=path,
        evidence=(
            {
                "target": target,
                "hops": len(path.hops),
                "basis": path.basis,
                "route": _route(path),
            },
        ),
        remediation=remediation,
    )


_PROMOTABLE_SEVERITY = {
    "unknown": "high",
    "simulated": "high",
    "inferred": "medium",
}


def _deputy_finding(
    graph: AttackGraph,
    grantor: str,
    deputy: str,
    delegation: AttackEdge,
    holds: list[AttackEdge],
    grantor_holds: set[str],
) -> Optional[WeaknessFinding]:
    """The confused-deputy finding for one grantor/deputy pair, if any.

    ``None`` when the grantor holds every capability the deputy holds: the
    delegation then adds nothing the grantor could not do directly.
    """

    beyond: dict[str, str] = {}
    for edge in holds:
        capability = _label(graph, edge.source)
        if capability in grantor_holds:
            continue
        weakest = min(
            (delegation.basis, edge.basis), key=lambda b: _BASIS_RANK.get(b, 0)
        )
        previous = beyond.get(capability)
        if previous is None or _BASIS_RANK.get(weakest, 0) > _BASIS_RANK.get(
            previous, 0
        ):
            beyond[capability] = weakest

    if not beyond:
        return None

    capabilities = tuple(sorted(beyond))
    strongest = max(beyond.values(), key=lambda b: _BASIS_RANK.get(b, 0))
    return WeaknessFinding(
        weakness_type="confused_deputy",
        description=(
            f"{deputy} takes delegation from {grantor} and holds "
            f"{', '.join(capabilities)}, which {grantor} does not hold"
        ),
        severity=_REACH_SEVERITY.get(strongest, "low"),
        basis=_capped(strongest),
        agents_involved=tuple(sorted((grantor, deputy))),
        evidence=(
            {
                "grantor": grantor,
                "deputy": deputy,
                "capabilities_beyond_grantor": list(capabilities),
                "basis": strongest,
            },
        ),
        remediation=(
            "bind the deputy's capabilities to the task that authorized "
            "them, so a delegation cannot invoke authority the grantor "
            "does not hold"
        ),
    )


def _promotable_finding(
    graph: AttackGraph,
    key: tuple[str, str, str],
    basis: str,
    resources: set[str],
    agents: set[str],
) -> WeaknessFinding:
    """One weakly-based edge, with the sensitive reach it carries."""

    source, target, edge_type = key
    reached = tuple(sorted(resources))
    return WeaknessFinding(
        weakness_type="promotable_provenance",
        description=(
            f"the {edge_type} edge {_label(graph, source)} -> "
            f"{_label(graph, target)} rests on a {basis} basis and carries "
            f"reach to {', '.join(reached)}"
        ),
        severity=_PROMOTABLE_SEVERITY.get(basis, "medium"),
        basis=_capped(basis),
        agents_involved=tuple(sorted(agents)),
        evidence=(
            {
                "edge": edge_type,
                "from": source,
                "to": target,
                "basis": basis,
                "resources_reached": list(reached),
            },
        ),
        remediation=(
            "establish this edge from an observation, or remove the "
            "authority it records"
        ),
    )


def _skipped(
    search_type: str,
    target: str,
    reason: str,
    elapsed: float,
) -> TwinSearchResult:
    """A search the shared budget left no room for.

    Reported rather than omitted: a missing search reads as a search that
    found nothing.
    """

    return TwinSearchResult(
        search_type=search_type,
        target=target,
        findings=(),
        search_space_explored=0,
        search_time=elapsed,
        terminated_early=True,
        termination_reason=reason,
    )


def _merge(
    search_type: str,
    results: list[TwinSearchResult],
) -> TwinSearchResult:
    """One result per search type, for searches run once per agent.

    ``search_time`` is summed because the runs are sequential. A single
    exhausted run marks the merged result exhausted: the type's coverage
    is partial whether one agent or all of them were cut short.
    """

    targets = {result.target for result in results}
    reasons = [
        result.termination_reason for result in results if result.terminated_early
    ]
    return TwinSearchResult(
        search_type=search_type,
        target=targets.pop() if len(targets) == 1 else "all_agents",
        findings=tuple(
            finding for result in results for finding in result.findings
        ),
        search_space_explored=sum(
            result.search_space_explored for result in results
        ),
        search_time=sum(result.search_time for result in results),
        terminated_early=bool(reasons),
        termination_reason=reasons[0] if reasons else "",
    )


class AdversarialDigitalTwin:
    """Bounded adversarial search for weaknesses in the recorded graph.

    ``graph_source`` is a callable returning the live
    :class:`~firewall.attackgraph.AttackGraph`. Every search deep-copies
    what it returns and reads only the copy, so a search cannot mutate
    production state and cannot see the graph change underneath it.

    ``clock`` is used for the deadline and for ``search_time``. Pin it to
    make searches reproducible.
    """

    def __init__(
        self,
        graph_source: Callable[[], AttackGraph],
        *,
        clock: Optional[Callable[[], float]] = None,
        max_nodes: int = MAX_SEARCH_NODES,
        timeout: float = SEARCH_TIMEOUT_SECONDS,
    ) -> None:
        if not callable(graph_source):
            raise TwinError("graph_source must be callable")
        self._graph_source = graph_source
        self._clock = clock or time.time
        self._max_nodes = max_nodes
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_network(
        cls,
        network: AgentNetworkGraph,
        **kwargs: Any,
    ) -> "AdversarialDigitalTwin":
        """A search over a v1.9 network graph, snapshotted per search."""

        def source() -> AttackGraph:
            return AttackGraph.from_network(network)

        return cls(source, **kwargs)

    @classmethod
    def from_graph(
        cls,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> "AdversarialDigitalTwin":
        """A search over an existing attack graph, read-only to it."""

        def source() -> AttackGraph:
            return graph

        return cls(source, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _snapshot(self) -> AttackGraph:
        """A deep copy of the live graph. Searches read only this."""

        return _clone(self._graph_source())

    def _budget(
        self,
        max_nodes: Optional[int],
        timeout: Optional[float],
    ) -> _Budget:
        return _Budget(
            self._clock,
            max_nodes=self._max_nodes if max_nodes is None else max_nodes,
            timeout=self._timeout if timeout is None else timeout,
        )

    @staticmethod
    def _result(
        search_type: str,
        target: str,
        findings: list[WeaknessFinding],
        budget: _Budget,
    ) -> TwinSearchResult:
        return TwinSearchResult(
            search_type=search_type,
            target=target,
            findings=tuple(findings),
            search_space_explored=budget.spent,
            search_time=budget.elapsed(),
            terminated_early=budget.exhausted,
            termination_reason=budget.reason,
        )

    # ------------------------------------------------------------------
    # Searches
    # ------------------------------------------------------------------

    def search_privilege_escalation(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Paths by which an agent reaches a sensitive resource.

        Reachability, not exploitability: the path shows recorded
        authority arriving at the resource, never that anything used it.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []

        for resource in _sensitive_resources(graph):
            if not budget.spend():
                break
            for path in graph.paths_to(
                resource.id,
                max_hops=max_depth,
                max_paths=MAX_PATHS_PER_TARGET,
            ):
                if not budget.spend(len(path.hops)):
                    break
                agent = _agent_label(graph, path.source)
                if agent is None:
                    continue
                findings.append(_reach_finding(
                    "privilege_escalation_path",
                    (agent,),
                    path,
                    f"sensitive resource {resource.label}",
                    remediation=(
                        "attenuate or revoke the capabilities on the "
                        f"path from {agent} to {resource.label}"
                    ),
                ))
            if budget.exhausted:
                break

        return self._result(
            "privilege_escalation",
            "sensitive_resources",
            findings,
            budget,
        )

    def search_trust_transitivity(
        self,
        *,
        max_hops: int = 6,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Trust chains that carry reach no direct relationship grants.

        The underlying analysis follows one branch per agent -- the first
        recorded ``trusts`` edge -- so a graph with several trust chains
        out of one agent is sampled, not enumerated. Its findings are
        ``inferred``, and this search does not promote them.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []

        for finding in graph.trust_transitivity(max_hops=max_hops):
            if not budget.spend():
                break
            findings.append(WeaknessFinding(
                weakness_type="trust_transitivity",
                description=finding.description,
                severity="medium",
                basis=_capped(finding.basis),
                agents_involved=tuple(finding.agents),
                evidence=(
                    {
                        "chain": list(finding.agents),
                        "basis": finding.basis,
                    },
                ),
                remediation=finding.response,
            ))

        return self._result(
            "trust_transitivity", "all_trust_chains", findings, budget
        )

    def search_compromised_agent_impact(
        self,
        agent: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """What one agent's compromise would put in reach.

        A conditional statement about recorded authority. It is not a
        claim that the agent is compromised, and nothing here contains
        it: containment is an authorized action taken elsewhere.

        An agent the graph does not record raises rather than returning an
        empty result. "No weaknesses found for an agent nobody has heard
        of" is a fail-open answer to a question that was never asked, and
        a node of some other type is a different question entirely.
        """

        graph = self._snapshot()
        node = graph.node(agent)
        if node is None or node.type != "agent":
            raise TwinError(f"no such agent in the graph: {agent}")
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []
        source = _label(graph, agent)

        for path in graph.paths_from_compromised(agent, max_hops=max_depth):
            if not budget.spend(len(path.hops)):
                break
            target = _label(graph, path.target)
            findings.append(_reach_finding(
                "compromised_agent_reach",
                (source,),
                path,
                target,
                description=(
                    f"if {source} were compromised it would reach "
                    f"{target} in {len(path.hops)} hop(s)"
                ),
                remediation=(
                    f"attenuate {source}'s capabilities, or place a "
                    f"chokepoint on the path to {target}"
                ),
            ))

        return self._result(
            "compromised_agent_impact", agent, findings, budget
        )

    def search_lateral_movement(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Indirect paths from one agent to another.

        A single edge between two agents is the recorded relationship, so
        only paths of two hops or more count as movement.

        ``agent_ids`` returns node ids, already prefixed. The first draft
        prefixed them again and searched for ``agent:agent:b``, which
        matches nothing: the search could not report a finding at all.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []
        agent_ids = graph.agent_ids()

        for index, source_id in enumerate(agent_ids):
            for target_id in agent_ids[index + 1:]:
                if not budget.spend():
                    break
                for path in graph.paths_to(
                    target_id,
                    max_hops=max_depth,
                    max_paths=10,
                    from_agents=[source_id],
                ):
                    if not budget.spend(len(path.hops)):
                        break
                    if len(path.hops) < 2:
                        continue
                    source = _label(graph, source_id)
                    target = _label(graph, target_id)
                    findings.append(_reach_finding(
                        "lateral_movement_path",
                        (source, target),
                        path,
                        target,
                        description=(
                            f"{source} reaches {target} indirectly, in "
                            f"{len(path.hops)} hops: {_route(path)}"
                        ),
                        remediation=(
                            f"review the trust and delegation edges "
                            f"between {source} and {target}"
                        ),
                    ))
                if budget.exhausted:
                    break
            if budget.exhausted:
                break

        return self._result(
            "lateral_movement", "all_agent_pairs", findings, budget
        )

    def search_multi_agent_attack_chains(
        self,
        *,
        min_agents: int = 3,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Delegation chains spanning ``min_agents`` or more agents.

        The first draft kept an agent's chains only when it had at least
        ``min_agents - 1`` of them, counting chains where it meant to
        count agents: a lone five-agent chain was discarded.
        """

        if isinstance(min_agents, bool) or not isinstance(min_agents, int):
            raise TwinError("min_agents must be an integer")
        if min_agents < 2:
            raise TwinError("a chain spans at least two agents")

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []
        reported: set[tuple[str, ...]] = set()

        for start_id in graph.agent_ids():
            for chain, basis in self._delegation_chains(
                graph, start_id, max_depth=max_depth, budget=budget
            ):
                if len(chain) < min_agents or chain in reported:
                    continue
                reported.add(chain)
                findings.append(WeaknessFinding(
                    weakness_type="multi_agent_attack_chain",
                    description=(
                        "delegation chain " + " -> ".join(chain)
                        + f" spans {len(chain)} agents"
                    ),
                    severity="medium",
                    basis=_capped(basis),
                    agents_involved=chain,
                    evidence=({"chain": list(chain), "basis": basis},),
                    remediation=(
                        "verify monotonic narrowing at every step of "
                        + " -> ".join(chain)
                    ),
                ))
            if budget.exhausted:
                break

        return self._result(
            "multi_agent_attack_chains", "all_agents", findings, budget
        )

    @staticmethod
    def _delegation_chains(
        graph: AttackGraph,
        start_id: str,
        *,
        max_depth: int,
        budget: _Budget,
    ) -> list[tuple[tuple[str, ...], str]]:
        """Delegation chains from ``start_id``, with each chain's basis.

        ``start_id`` is a node id, not a bare agent name. Every expansion
        is charged to the budget, so a densely delegated graph stops at
        the node ceiling instead of enumerating exponentially many paths.

        A chain is a simple path: an edge back to an agent already on the
        path is not followed and not recorded. Recording it would report
        ``a -> b -> c -> a`` as spanning four agents when it spans three,
        and ``min_agents`` counts agents.
        """

        if graph.node(start_id) is None:
            return []

        chains: list[tuple[tuple[str, ...], str]] = []
        queue: deque[tuple[str, tuple[str, ...], tuple[str, ...], str]] = (
            deque([(start_id, (start_id,), (_label(graph, start_id),),
                    "observed")])
        )

        while queue:
            node_id, visited, labels, basis = queue.popleft()
            if len(labels) >= max_depth:
                continue
            if not budget.spend():
                break

            for edge in graph.edges():
                if edge.type != "delegates" or edge.source != node_id:
                    continue
                target = graph.node(edge.target)
                if target is None or target.type != "agent":
                    continue
                if edge.target in visited:
                    continue
                weakest = min(
                    (basis, edge.basis), key=lambda b: _BASIS_RANK.get(b, 0)
                )
                extended = labels + (target.label,)
                chains.append((extended, weakest))
                queue.append((
                    edge.target,
                    visited + (edge.target,),
                    extended,
                    weakest,
                ))

        return chains

    def search_unenforced_revocation(
        self,
        *,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Recorded revocations the reachability analysis does not honour.

        :meth:`AttackGraph.reachable` excludes a revoked capability only
        when the ``derived_from`` edge recording the revocation carries an
        ``observed`` basis. A revocation recorded on a weaker basis sits
        in the graph and changes nothing, which is the one revocation
        weakness a graph search can establish. It says nothing about
        ``FirewallSDK.authorize``, whose revocation gate reads the
        revocation store rather than this graph.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        findings: list[WeaknessFinding] = []

        for edge in graph.edges():
            if edge.type != "derived_from":
                continue
            if not edge.attributes.get("revoked"):
                continue
            if not budget.spend():
                break
            if edge.basis == "observed":
                continue

            capability = _label(graph, edge.source)
            still = _reaching(graph, capability)
            findings.append(WeaknessFinding(
                weakness_type="unenforced_revocation",
                description=(
                    f"the revocation of {capability} is recorded on a "
                    f"{edge.basis} edge, and reachability honours only "
                    "observed revocations"
                    + (f"; {', '.join(still)} still reach it" if still
                       else "; no agent reaches it by another edge")
                ),
                severity="critical" if still else "high",
                basis=_capped(edge.basis),
                agents_involved=still,
                evidence=(
                    {
                        "capability": capability,
                        "edge_basis": edge.basis,
                        "still_reaching": list(still),
                    },
                ),
                remediation=(
                    "record the revocation on an observed edge, or "
                    "remove the holds edge it revokes"
                ),
            ))

        return self._result(
            "unenforced_revocation", "all_revocations", findings, budget
        )

    def search_promotable_provenance(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Weakly-based edges that carry reach to a sensitive resource.

        Only edges *on a path to a sensitive resource* are reported, one
        finding per edge, listing the resources reached through it. The
        first draft reported every non-observed edge in the graph, which
        says little more than "this graph contains inferences".

        Severity ranks how far the recorded reach outruns its evidence:
        ``unknown`` and ``simulated`` bases rest on no observation at all
        -- and a simulated edge on a live reachability path is a
        containment failure in its own right -- while ``inferred`` was at
        least concluded from something. Neither is exploitation.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)
        # edge key -> (basis, resources reached, agents traversing)
        weak: dict[tuple[str, str, str], tuple[str, set[str], set[str]]] = {}

        for resource in _sensitive_resources(graph):
            if not budget.spend():
                break
            for path in graph.paths_to(
                resource.id,
                max_hops=max_depth,
                max_paths=MAX_PATHS_PER_TARGET,
            ):
                if not budget.spend(len(path.hops)):
                    break
                agent = _agent_label(graph, path.source)
                for hop in path.hops:
                    if _BASIS_RANK.get(hop["basis"], 0) >= _BASIS_RANK["derived"]:
                        continue
                    key = (hop["from"], hop["to"], hop["edge"])
                    entry = weak.setdefault(
                        key, (hop["basis"], set(), set())
                    )
                    entry[1].add(resource.label)
                    if agent is not None:
                        entry[2].add(agent)
            if budget.exhausted:
                break

        findings = [
            _promotable_finding(graph, key, *value)
            for key, value in weak.items()
        ]
        return self._result(
            "promotable_provenance", "sensitive_resources", findings, budget
        )

    def search_confused_deputy(
        self,
        *,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> TwinSearchResult:
        """Delegations that let a grantor direct authority it lacks.

        A deputy that holds a capability and takes delegation from a
        grantor acts on the grantor's behalf with its own authority. That
        is only a weakness where the grantor does not hold the capability
        itself: then the delegation reaches past what the grantor could do
        directly. The first draft reported every delegated-to agent
        holding any capability, including the ordinary case where the
        grantor holds strictly more.

        The comparison is against what the grantor *holds*, not what it
        reaches. Reach is the wrong test and silently empties this search:
        :meth:`AttackGraph.reachable` follows the delegation edge into the
        deputy's capabilities, so a grantor's reach always contains them
        and no delegation could ever be reported.

        One finding per grantor/deputy pair, listing the capabilities the
        grantor does not hold. Severity follows the same rule as the path
        searches: the weakest of the two edges decides, because a
        conclusion is no better founded than its weakest link.
        """

        graph = self._snapshot()
        budget = self._budget(max_nodes, timeout)

        # holds runs capability -> agent; delegates runs agent -> agent.
        holds: dict[str, list[AttackEdge]] = {}
        delegated_to: dict[str, list[AttackEdge]] = {}
        for edge in graph.edges():
            if edge.type == "holds":
                holds.setdefault(edge.target, []).append(edge)
            elif edge.type == "delegates":
                delegated_to.setdefault(edge.target, []).append(edge)

        findings: list[WeaknessFinding] = []

        for deputy_id, incoming in delegated_to.items():
            deputy = _agent_label(graph, deputy_id)
            if deputy is None or deputy_id not in holds:
                continue
            for delegation in incoming:
                if not budget.spend():
                    break
                grantor = _agent_label(graph, delegation.source)
                if grantor is None:
                    continue
                own = {
                    _label(graph, edge.source)
                    for edge in holds.get(delegation.source, ())
                }
                finding = _deputy_finding(
                    graph, grantor, deputy, delegation,
                    holds[deputy_id], own,
                )
                if finding is not None:
                    findings.append(finding)
            if budget.exhausted:
                break

        return self._result(
            "confused_deputy", "all_delegations", findings, budget
        )

    # ------------------------------------------------------------------
    # Running every search
    # ------------------------------------------------------------------

    def run_full_adversarial_search(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, TwinSearchResult]:
        """Every search in :data:`SEARCH_TYPES`, under one shared bound.

        The node ceiling and the deadline apply to the run as a whole, not
        to each search: a graph that exhausts the budget in the first
        search does not then get a fresh budget for the ninth. Searches
        the budget leaves no room for are reported as terminated with the
        reason, never omitted.

        The per-agent search -- the blast radius of one compromised agent
        -- runs once per agent and is merged into a single result, so the
        returned mapping has exactly one entry per search type.

        Each search takes its own snapshot, so a graph mutated while this
        runs can be seen differently by two of them. Every snapshot is
        still a copy: nothing here writes to the live graph.
        """

        total_nodes = self._max_nodes if max_nodes is None else max_nodes
        total_time = self._timeout if timeout is None else timeout
        start = float(self._clock())
        plan = self._plan(self._snapshot().agent_ids(), max_depth)

        spent = 0
        collected: dict[str, list[TwinSearchResult]] = {}
        for search_type, target, run in plan:
            nodes_left = total_nodes - spent
            time_left = total_time - (float(self._clock()) - start)
            if nodes_left <= 0 or time_left <= 0:
                result = _skipped(
                    search_type,
                    target,
                    "node_limit" if nodes_left <= 0 else "timeout",
                    float(self._clock()) - start,
                )
            else:
                result = run(nodes_left, time_left)
                spent += result.search_space_explored
            collected.setdefault(search_type, []).append(result)

        return {
            search_type: _merge(search_type, collected.get(search_type, []))
            for search_type in SEARCH_TYPES
        }

    def _plan(
        self,
        agents: tuple[str, ...],
        max_depth: int,
    ) -> list[tuple[str, str, Callable[[int, float], TwinSearchResult]]]:
        """The full run, as (type, target, runner) in execution order.

        Each runner takes the nodes and seconds left in the shared budget.
        ``agent`` is bound as a default argument in the per-agent runners:
        a closure over the loop variable would give every runner the last
        agent.
        """

        plan: list[tuple[str, str, Callable[[int, float], TwinSearchResult]]] = [
            ("privilege_escalation", "sensitive_resources",
             lambda n, t: self.search_privilege_escalation(
                 max_depth=max_depth, max_nodes=n, timeout=t)),
            ("trust_transitivity", "all_trust_chains",
             lambda n, t: self.search_trust_transitivity(
                 max_nodes=n, timeout=t)),
        ]
        for agent in agents:
            plan.append((
                "compromised_agent_impact", agent,
                lambda n, t, agent=agent: self.search_compromised_agent_impact(
                    agent, max_depth=max_depth, max_nodes=n, timeout=t),
            ))
        plan.extend([
            ("lateral_movement", "all_agent_pairs",
             lambda n, t: self.search_lateral_movement(
                 max_depth=max_depth, max_nodes=n, timeout=t)),
            ("multi_agent_attack_chains", "all_agents",
             lambda n, t: self.search_multi_agent_attack_chains(
                 max_depth=max_depth, max_nodes=n, timeout=t)),
            ("unenforced_revocation", "all_revocations",
             lambda n, t: self.search_unenforced_revocation(
                 max_nodes=n, timeout=t)),
            ("promotable_provenance", "sensitive_resources",
             lambda n, t: self.search_promotable_provenance(
                 max_depth=max_depth, max_nodes=n, timeout=t)),
            ("confused_deputy", "all_delegations",
             lambda n, t: self.search_confused_deputy(
                 max_nodes=n, timeout=t)),
        ])
        return plan

    def run(self, search_type: str, **kwargs: Any) -> TwinSearchResult:
        """One search by name, for callers driven by configuration.

        An unknown name raises rather than returning an empty result: a
        result claiming a search ran when no such search exists would be
        the same lie as a search that silently found nothing.
        """

        if search_type not in SEARCH_TYPES:
            raise TwinError(f"unknown search type: {search_type}")
        return getattr(self, f"search_{search_type}")(**kwargs)
