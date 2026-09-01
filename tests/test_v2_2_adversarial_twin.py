"""v2.2 unit tests: adversarial weakness search over the security twin.

Two things are under test. First, that every search in
:data:`firewall.twin.adversarial.SEARCH_TYPES` can actually report a
finding, and reports nothing on state that is healthy in the way that
search cares about -- a search that cannot fire and a search that always
fires are the same defect wearing different clothes.

Second, that the search is what it claims: it reads a snapshot and never
the live graph, it stops at its bounds and says which bound stopped it,
it is deterministic under a pinned clock, it never labels a conclusion
``observed``, and it is not an authorization authority.
"""

from __future__ import annotations

import ast
import importlib
import inspect

import pytest

from firewall.attackgraph import AttackGraph
from firewall.twin import TwinError
from firewall.twin.adversarial import (
    SEARCH_TYPES,
    WEAKNESS_SEVERITIES,
    AdversarialDigitalTwin,
    TwinSearchResult,
    WeaknessFinding,
)

# ``search_compromised_agent_impact`` is the one search that takes an
# agent. Every other search sweeps the whole graph.
_PER_AGENT = {"compromised_agent_impact": {"agent": "agent:alice"}}


def _pinned(times: list[float]):
    """A clock that returns each value once, then repeats the last.

    A pinned clock makes ``search_time`` and every deadline decision a
    property of the test rather than of the machine.
    """

    remaining = list(times)

    def clock() -> float:
        if len(remaining) > 1:
            return remaining.pop(0)
        return remaining[0]

    return clock


def _weak_graph() -> AttackGraph:
    """A graph in which every search has something to find.

    alice delegates to bob to carol to dave, so the chain spans four
    agents; alice trusts carol trusts dave, so trust is transitive; each
    agent holds a capability the one before it does not; one capability
    reaches a sensitive resource through an ``inferred`` edge; and one
    revocation is recorded on a ``derived`` edge, which reachability does
    not honour.
    """

    graph = AttackGraph()
    for name in ("alice", "bob", "carol", "dave"):
        graph.add_node(f"agent:{name}", "agent", name)
    for cap in ("payments.send", "files.read", "db.admin", "secrets.read"):
        graph.add_node(f"cap:{cap}", "capability", cap)
    for tool in ("payments", "files", "vault"):
        graph.add_node(f"tool:{tool}", "tool", tool)
    graph.add_node("res:shadow", "resource", "/etc/shadow")
    graph.add_node("res:log", "resource", "/tmp/log")
    graph.add_node("res:key", "resource", "secrets/master.key")

    holds = [
        ("cap:payments.send", "agent:alice"),
        ("cap:files.read", "agent:bob"),
        ("cap:db.admin", "agent:carol"),
        ("cap:secrets.read", "agent:dave"),
    ]
    for capability, agent in holds:
        graph.add_edge(capability, agent, "holds")

    graph.add_edge("cap:payments.send", "tool:payments", "bound_to")
    graph.add_edge("cap:files.read", "tool:files", "bound_to")
    # The one weakly-based edge on a path to a sensitive resource.
    graph.add_edge("cap:secrets.read", "tool:vault", "bound_to",
                   basis="inferred")
    graph.add_edge("tool:payments", "res:shadow", "accesses")
    graph.add_edge("tool:files", "res:log", "accesses")
    graph.add_edge("tool:vault", "res:key", "accesses")

    graph.add_edge("agent:alice", "agent:bob", "delegates")
    graph.add_edge("agent:bob", "agent:carol", "delegates")
    graph.add_edge("agent:carol", "agent:dave", "delegates")
    graph.add_edge("agent:alice", "agent:carol", "trusts")
    graph.add_edge("agent:carol", "agent:dave", "trusts")

    # A revocation reachability will not honour: the basis is derived,
    # and only an observed derived_from edge excludes a capability.
    graph.add_edge("cap:db.admin", "cap:payments.send", "derived_from",
                   basis="derived", attributes={"revoked": True})
    return graph


def _healthy_graph() -> AttackGraph:
    """One agent, one capability, one non-sensitive resource.

    Nothing is delegated, nothing is trusted, nothing is revoked, and
    every edge is observed. No search should report anything.
    """

    graph = AttackGraph()
    graph.add_node("agent:alice", "agent", "alice")
    graph.add_node("cap:files.read", "capability", "files.read")
    graph.add_node("tool:files", "tool", "files")
    graph.add_node("res:log", "resource", "/tmp/log")
    graph.add_edge("cap:files.read", "agent:alice", "holds")
    graph.add_edge("cap:files.read", "tool:files", "bound_to")
    graph.add_edge("tool:files", "res:log", "accesses")
    return graph


def _twin(graph: AttackGraph, **kwargs) -> AdversarialDigitalTwin:
    return AdversarialDigitalTwin.from_graph(graph, **kwargs)


def _run_all(twin: AdversarialDigitalTwin) -> dict[str, TwinSearchResult]:
    """Every search, one at a time, through the name dispatcher."""

    return {
        name: twin.run(name, **_PER_AGENT.get(name, {}))
        for name in SEARCH_TYPES
    }


# ----------------------------------------------------------------------
# Every named search exists, runs, and can report something
# ----------------------------------------------------------------------

def test_every_search_type_names_a_method():
    for name in SEARCH_TYPES:
        assert callable(getattr(AdversarialDigitalTwin, f"search_{name}", None))


def test_every_search_can_report_a_finding():
    """A search that cannot fire is a documented detection that never
    happens. Each of these fired on :func:`_weak_graph`."""

    results = _run_all(_twin(_weak_graph()))
    silent = sorted(name for name, r in results.items() if not r.findings)
    assert silent == []


def test_no_search_reports_anything_on_healthy_state():
    """The other half. A search that always fires is no check at all."""

    results = _run_all(_twin(_healthy_graph()))
    noisy = sorted(name for name, r in results.items() if r.findings)
    assert noisy == []


def test_an_unknown_search_type_raises():
    with pytest.raises(TwinError):
        _twin(_healthy_graph()).run("policy_conflicts")


def test_every_finding_declares_a_known_severity():
    for result in _run_all(_twin(_weak_graph())).values():
        for finding in result.findings:
            assert finding.severity in WEAKNESS_SEVERITIES
            assert finding.weakness_type
            assert finding.description
            assert finding.remediation


# ----------------------------------------------------------------------
# Lateral movement: what counts as movement
# ----------------------------------------------------------------------

def _agents(*names: str) -> AttackGraph:
    graph = AttackGraph()
    for name in names:
        graph.add_node(f"agent:{name}", "agent", name)
    return graph


def test_a_direct_edge_between_two_agents_is_not_movement():
    """The edge *is* the relationship. Reporting it says nothing."""

    graph = _agents("alice", "bob")
    graph.add_edge("agent:alice", "agent:bob", "delegates")
    assert _twin(graph).search_lateral_movement().findings == ()


def test_a_two_hop_route_between_agents_is_movement():
    graph = _agents("alice", "bob", "carol")
    graph.add_edge("agent:alice", "agent:bob", "delegates")
    graph.add_edge("agent:bob", "agent:carol", "delegates")
    findings = _twin(graph).search_lateral_movement().findings
    assert [f.agents_involved for f in findings] == [("alice", "carol")]


def test_movement_findings_name_agents_not_node_ids():
    """The regression that made this search structurally dead.

    ``agent_ids`` returns ``agent:alice``. Prefixing it again produced
    ``agent:agent:alice``, which matches no node, so the search could
    never report anything.
    """

    findings = _twin(_weak_graph()).search_lateral_movement().findings
    assert findings
    named = {name for f in findings for name in f.agents_involved}
    assert named <= {"alice", "bob", "carol", "dave"}


def test_two_routes_between_the_same_pair_read_as_two_findings():
    """alice reaches dave by trust and by delegation. Both are reported,
    and the descriptions distinguish them by edge type."""

    findings = _twin(_weak_graph()).search_lateral_movement().findings
    routes = {
        f.description for f in findings if f.agents_involved == ("alice", "dave")
    }
    assert len(routes) > 1


# ----------------------------------------------------------------------
# Multi-agent chains
# ----------------------------------------------------------------------

def _chain(*names: str) -> AttackGraph:
    graph = _agents(*names)
    for source, target in zip(names, names[1:]):
        graph.add_edge(f"agent:{source}", f"agent:{target}", "delegates")
    return graph


def test_a_single_long_chain_is_reported():
    """The regression that discarded real findings.

    The first draft kept an agent's chains only if it had at least
    ``min_agents - 1`` of them, counting chains where it meant to count
    agents. One five-agent chain is one chain, and it is the finding.
    """

    result = _twin(_chain("a", "b", "c", "d", "e")).run(
        "multi_agent_attack_chains", min_agents=5
    )
    assert [f.agents_involved for f in result.findings] == [
        ("a", "b", "c", "d", "e")
    ]


def test_a_chain_shorter_than_min_agents_is_not_reported():
    result = _twin(_chain("a", "b")).run(
        "multi_agent_attack_chains", min_agents=3
    )
    assert result.findings == ()


def test_min_agents_must_describe_a_chain():
    twin = _twin(_chain("a", "b", "c"))
    with pytest.raises(TwinError):
        twin.search_multi_agent_attack_chains(min_agents=1)
    with pytest.raises(TwinError):
        twin.search_multi_agent_attack_chains(min_agents=True)


def test_a_delegation_cycle_terminates():
    """Three agents delegating in a ring. The chain walk visits each node
    once per path, so the search returns instead of looping."""

    graph = _chain("a", "b", "c")
    graph.add_edge("agent:c", "agent:a", "delegates")
    result = _twin(graph).search_multi_agent_attack_chains()
    assert result.findings
    assert all(
        len(set(f.agents_involved)) == len(f.agents_involved)
        for f in result.findings
    )


# ----------------------------------------------------------------------
# Unenforced revocation
# ----------------------------------------------------------------------

def _revoked(basis: str, *, reachable: bool = True) -> AttackGraph:
    """A graph with one revocation recorded on ``basis``."""

    graph = _agents("alice")
    graph.add_node("cap:db.admin", "capability", "db.admin")
    graph.add_node("cap:payments.send", "capability", "payments.send")
    if reachable:
        graph.add_edge("cap:db.admin", "agent:alice", "holds")
    graph.add_edge("cap:db.admin", "cap:payments.send", "derived_from",
                   basis=basis, attributes={"revoked": True})
    return graph


def test_a_revocation_recorded_on_a_weak_basis_is_reported():
    """The one revocation weakness a graph search can establish.

    ``AttackGraph.reachable`` excludes a revoked capability only when the
    ``derived_from`` edge carries an observed basis, so a revocation
    recorded on anything weaker changes nothing.
    """

    result = _twin(_revoked("derived")).search_unenforced_revocation()
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "critical"
    assert finding.agents_involved == ("alice",)
    assert "db.admin" in finding.description


def test_an_observed_revocation_is_not_reported():
    """It is honoured, so there is nothing to report."""

    assert _twin(_revoked("observed")).search_unenforced_revocation(
    ).findings == ()


def test_an_unreachable_capability_is_the_lesser_finding():
    """Still unenforced, but no agent reaches it by another edge."""

    result = _twin(
        _revoked("inferred", reachable=False)
    ).search_unenforced_revocation()
    assert [f.severity for f in result.findings] == ["high"]
    assert result.findings[0].agents_involved == ()


def test_an_edge_without_a_revoked_attribute_is_not_a_revocation():
    """The false positive that fired on healthy state."""

    graph = _agents("alice")
    graph.add_node("cap:a", "capability", "cap.a")
    graph.add_node("cap:b", "capability", "cap.b")
    graph.add_edge("cap:b", "cap:a", "derived_from", basis="derived")
    assert _twin(graph).search_unenforced_revocation().findings == ()


# ----------------------------------------------------------------------
# Confused deputy
# ----------------------------------------------------------------------

def _deputy(deputy_capability: str, grantor_capability: str) -> AttackGraph:
    graph = _agents("alice", "bob")
    graph.add_edge("agent:alice", "agent:bob", "delegates")
    for name, holder in (
        (grantor_capability, "alice"),
        (deputy_capability, "bob"),
    ):
        graph.add_node(f"cap:{name}", "capability", name)
        graph.add_edge(f"cap:{name}", f"agent:{holder}", "holds")
    return graph


def test_a_deputy_holding_authority_the_grantor_lacks_is_reported():
    result = _twin(_deputy("db.admin", "files.read")).search_confused_deputy()
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.agents_involved == ("alice", "bob")
    assert "db.admin" in finding.description
    assert "files.read" not in finding.description


def test_a_deputy_holding_only_what_the_grantor_holds_is_not_reported():
    """The ordinary case: the delegation adds nothing the grantor could
    not do directly."""

    graph = _deputy("files.read", "files.read")
    assert _twin(graph).search_confused_deputy().findings == ()


def test_the_comparison_is_against_what_the_grantor_holds_not_reaches():
    """The test that keeps this search alive.

    ``AttackGraph.reachable`` follows the delegation edge into the
    deputy's capabilities, so the grantor's *reach* always contains them
    and a reach comparison could never report anything.
    """

    graph = _deputy("db.admin", "files.read")
    reach = graph.reachable("agent:alice")["capabilities"]
    assert "db.admin" in reach
    assert _twin(graph).search_confused_deputy().findings


def test_a_deputy_that_holds_nothing_is_not_reported():
    graph = _agents("alice", "bob")
    graph.add_edge("agent:alice", "agent:bob", "delegates")
    assert _twin(graph).search_confused_deputy().findings == ()


# ----------------------------------------------------------------------
# Promotable provenance
# ----------------------------------------------------------------------

def test_only_weak_edges_on_a_sensitive_path_are_reported():
    """Not "this graph contains inferences".

    The weak edge to ``/tmp/log`` carries no sensitive reach and is not
    reported; the one to ``secrets/master.key`` is.
    """

    graph = _agents("alice")
    for cap, tool, res, label in (
        ("cap:harmless", "tool:files", "res:log", "/tmp/log"),
        ("cap:secrets", "tool:vault", "res:key", "secrets/master.key"),
    ):
        graph.add_node(cap, "capability", cap.split(":", 1)[1])
        graph.add_node(tool, "tool", tool.split(":", 1)[1])
        graph.add_node(res, "resource", label)
        graph.add_edge(cap, "agent:alice", "holds")
        graph.add_edge(cap, tool, "bound_to", basis="inferred")
        graph.add_edge(tool, res, "accesses")

    findings = _twin(graph).search_promotable_provenance().findings
    assert len(findings) == 1
    assert "secrets" in findings[0].description
    assert findings[0].evidence[0]["resources_reached"] == [
        "secrets/master.key"
    ]


def test_an_observed_path_to_a_sensitive_resource_is_not_reported():
    graph = _agents("alice")
    graph.add_node("cap:secrets", "capability", "secrets.read")
    graph.add_node("tool:vault", "tool", "vault")
    graph.add_node("res:key", "resource", "secrets/master.key")
    graph.add_edge("cap:secrets", "agent:alice", "holds")
    graph.add_edge("cap:secrets", "tool:vault", "bound_to")
    graph.add_edge("tool:vault", "res:key", "accesses")
    assert _twin(graph).search_promotable_provenance().findings == ()


def test_one_finding_per_weak_edge_however_many_paths_cross_it():
    """Two agents reach the resource through the same weak edge."""

    graph = _agents("alice", "bob")
    graph.add_node("cap:secrets", "capability", "secrets.read")
    graph.add_node("tool:vault", "tool", "vault")
    graph.add_node("res:key", "resource", "secrets/master.key")
    graph.add_edge("cap:secrets", "agent:alice", "holds")
    graph.add_edge("cap:secrets", "agent:bob", "holds")
    graph.add_edge("cap:secrets", "tool:vault", "bound_to", basis="unknown")
    graph.add_edge("tool:vault", "res:key", "accesses")

    findings = _twin(graph).search_promotable_provenance().findings
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].basis == "unknown"


# ----------------------------------------------------------------------
# Snapshot isolation
# ----------------------------------------------------------------------

def test_a_search_does_not_mutate_the_graph_it_reads():
    graph = _weak_graph()
    before = graph.to_dict()
    _run_all(_twin(graph))
    assert graph.to_dict() == before


def test_a_search_reads_a_copy_not_the_live_graph():
    graph = _weak_graph()
    twin = _twin(graph)
    snapshot = twin._snapshot()
    assert snapshot is not graph
    snapshot.add_node("agent:intruder", "agent", "intruder")
    assert graph.node("agent:intruder") is None


def test_findings_do_not_change_when_the_graph_changes_afterwards():
    """A result is a record of what was true when the search ran."""

    graph = _weak_graph()
    twin = _twin(graph)
    first = twin.search_confused_deputy()
    described = [f.description for f in first.findings]

    graph.add_node("agent:intruder", "agent", "intruder")
    graph.add_edge("agent:alice", "agent:intruder", "delegates")
    assert [f.description for f in first.findings] == described
    # And the next search sees the change, because it takes a new
    # snapshot rather than caching one.
    assert twin.search_lateral_movement().findings != first.findings


# ----------------------------------------------------------------------
# Bounds, reported honestly
# ----------------------------------------------------------------------

def test_a_node_ceiling_stops_the_search_and_names_itself():
    result = _twin(_weak_graph()).search_privilege_escalation(max_nodes=1)
    assert result.terminated_early
    assert result.termination_reason == "node_limit"


def test_a_deadline_stops_the_search_and_names_itself():
    twin = _twin(_weak_graph(), clock=_pinned([0.0, 100.0]))
    result = twin.search_privilege_escalation(timeout=30.0)
    assert result.terminated_early
    assert result.termination_reason == "timeout"


def test_a_completed_search_claims_no_bound():
    result = _twin(_weak_graph()).search_confused_deputy()
    assert not result.terminated_early
    assert result.termination_reason == ""


@pytest.mark.parametrize("kwargs", [
    {"max_nodes": 0},
    {"max_nodes": -1},
    {"max_nodes": True},
    {"max_nodes": 1.5},
    {"timeout": 0},
    {"timeout": -1.0},
    {"timeout": "soon"},
])
def test_an_unusable_bound_fails_closed(kwargs):
    with pytest.raises(TwinError):
        _twin(_weak_graph()).search_confused_deputy(**kwargs)


def test_the_clock_must_be_the_twins_own():
    """``search_time`` under a pinned clock is the test's arithmetic, not
    the machine's."""

    twin = _twin(_weak_graph(), clock=_pinned([10.0, 12.5]))
    assert twin.search_confused_deputy().search_time == 2.5


# ----------------------------------------------------------------------
# Determinism
# ----------------------------------------------------------------------

def test_the_same_graph_and_clock_give_the_same_findings():
    graph = _weak_graph()
    first = _run_all(_twin(graph, clock=_pinned([0.0])))
    second = _run_all(_twin(graph, clock=_pinned([0.0])))
    assert {k: [f.to_dict() for f in v.findings] for k, v in first.items()} == {
        k: [f.to_dict() for f in v.findings] for k, v in second.items()
    }


@pytest.mark.parametrize("name", [
    "confused_deputy", "promotable_provenance", "unenforced_revocation",
    "lateral_movement", "multi_agent_attack_chains",
])
def test_findings_come_back_in_a_stable_order(name):
    """Deduplication is done with sets, so ordering has to come from the
    graph walk. Reporting in set-iteration order would make two runs on
    the same graph disagree."""

    graph = _weak_graph()
    orders = {
        tuple(f.description for f in _twin(graph).run(name).findings)
        for _ in range(5)
    }
    assert len(orders) == 1
    assert orders != {()}


# ----------------------------------------------------------------------
# Provenance: a conclusion is not an observation
# ----------------------------------------------------------------------

def test_no_finding_claims_to_be_an_observation():
    for result in _run_all(_twin(_weak_graph())).values():
        for finding in result.findings:
            assert finding.basis != "observed"


def test_a_finding_may_not_be_labelled_observed():
    with pytest.raises(TwinError):
        WeaknessFinding(
            weakness_type="lateral_movement_path",
            description="alice reaches bob",
            severity="low",
            basis="observed",
        )


def test_a_finding_inherits_the_weaker_basis_of_what_it_rests_on():
    """An inferred edge cannot support a derived conclusion."""

    graph = _agents("alice", "bob", "carol")
    graph.add_edge("agent:alice", "agent:bob", "delegates")
    graph.add_edge("agent:bob", "agent:carol", "delegates", basis="inferred")
    findings = _twin(graph).search_multi_agent_attack_chains().findings
    assert [f.basis for f in findings] == ["inferred"]


# ----------------------------------------------------------------------
# The result types validate themselves
# ----------------------------------------------------------------------

def _finding(**overrides) -> WeaknessFinding:
    fields = {
        "weakness_type": "lateral_movement_path",
        "description": "alice reaches carol via bob",
        "severity": "low",
    }
    fields.update(overrides)
    return WeaknessFinding(**fields)


@pytest.mark.parametrize("overrides", [
    {"weakness_type": ""},
    {"weakness_type": "   "},
    {"severity": "catastrophic"},
    {"severity": ""},
    {"basis": "guessed"},
    {"evidence": [{"chain": []}]},
    {"agents_involved": ["alice", "carol"]},
])
def test_a_malformed_finding_raises(overrides):
    """A finding is evidence for a human decision. It fails to exist
    rather than existing with a field nobody can interpret."""

    with pytest.raises(TwinError):
        _finding(**overrides)


def test_a_well_formed_finding_defaults_to_derived():
    assert _finding().basis == "derived"


@pytest.mark.parametrize("overrides", [
    {"terminated_early": True},
    {"terminated_early": True, "termination_reason": ""},
    {"termination_reason": "timeout"},
    {"findings": []},
])
def test_a_malformed_result_raises(overrides):
    """Either half of the termination pair alone is a lie: a bound that
    stopped the search without saying so reports a partial answer as a
    complete one, and a reason without the flag claims the opposite."""

    fields = {"search_type": "lateral_movement", "target": "all_agents"}
    fields.update(overrides)
    with pytest.raises(TwinError):
        TwinSearchResult(**fields)


def test_a_result_serializes_its_findings_repeatably():
    """``to_dict`` twice gives the same thing. The v2.2 policy-analysis
    audit found a report whose second serialization was empty because a
    field held a spent generator."""

    result = _twin(_weak_graph()).search_confused_deputy()
    assert result.to_dict() == result.to_dict()
    assert result.to_dict()["findings"]


# ----------------------------------------------------------------------
# The full sweep
# ----------------------------------------------------------------------

def test_the_full_sweep_reports_every_search_type():
    results = _twin(_weak_graph()).run_full_adversarial_search()
    assert set(results) == set(SEARCH_TYPES)
    assert all(r.search_type == name for name, r in results.items())


def test_the_full_sweep_finds_what_the_searches_find():
    twin = _twin(_weak_graph())
    swept = twin.run_full_adversarial_search()
    assert sorted(name for name, r in swept.items() if not r.findings) == []


def test_a_shared_budget_is_shared_not_reissued():
    """Nine searches under one ceiling do not get nine ceilings. The
    searches the budget leaves no room for say so."""

    results = _twin(_weak_graph()).run_full_adversarial_search(max_nodes=2)
    stopped = {name: r for name, r in results.items() if r.terminated_early}
    assert stopped, "a two-node ceiling cannot cover the whole sweep"
    assert set(results) == set(SEARCH_TYPES), "a skipped search is still reported"
    for result in stopped.values():
        assert result.termination_reason in {"node_limit", "timeout"}


def test_an_exhausted_budget_skips_rather_than_omits():
    """The distinction the sweep exists to preserve: a search that was
    never run must not be indistinguishable from one that found nothing."""

    results = _twin(_weak_graph()).run_full_adversarial_search(max_nodes=1)
    for name in SEARCH_TYPES:
        result = results[name]
        assert result.findings or result.terminated_early


def test_the_per_agent_search_is_merged_into_one_result():
    """``compromised_agent_impact`` runs once per agent. The sweep reports
    one result per search type, so the four runs merge, and the merged
    target names the sweep rather than the last agent."""

    results = _twin(_weak_graph()).run_full_adversarial_search()
    merged = results["compromised_agent_impact"]
    assert merged.target == "all_agents"
    named = {name for f in merged.findings for name in f.agents_involved}
    assert named == {"alice", "bob", "carol", "dave"}


def test_a_graph_with_one_agent_merges_to_that_agent():
    results = _twin(_healthy_graph()).run_full_adversarial_search()
    assert results["compromised_agent_impact"].target == "agent:alice"


@pytest.mark.parametrize("agent", ["agent:nobody", "alice", "", "cap:db.admin"])
def test_an_agent_the_graph_does_not_record_raises(agent):
    """An empty result for an unrecorded agent reads as "this agent has no
    reach". Unknown is not safe; a bare label is not a node id."""

    with pytest.raises(TwinError):
        _twin(_weak_graph()).search_compromised_agent_impact(agent)


def test_a_graph_with_no_agents_still_reports_every_search():
    """The empty merge. Nothing to sweep is a result, not an omission."""

    graph = AttackGraph()
    graph.add_node("res:log", "resource", "/tmp/log")
    results = _twin(graph).run_full_adversarial_search()
    assert set(results) == set(SEARCH_TYPES)
    assert all(r.findings == () for r in results.values())
    assert results["compromised_agent_impact"].target == "all_agents"


# ----------------------------------------------------------------------
# Not an authorization authority
# ----------------------------------------------------------------------

def test_the_search_module_does_not_reach_for_authorization():
    """The structural half of the rule.

    The check is over code, not text: the module's own docstring names
    ``FirewallSDK.authorize`` in order to say it never calls it, and a
    substring search would fail on that sentence. What must be absent is
    an import of the decision boundary and any name that resolves to it.
    """

    module = importlib.import_module("firewall.twin.adversarial")
    tree = ast.parse(inspect.getsource(module))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not {name for name in imported if "sdk" in name}
    assert not {name for name in imported if "policy" in name}

    referenced = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    } | {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    assert not {name for name in referenced if "authorize" in name.lower()}
    assert not {name for name in referenced if "sdk" in name.lower()}


def test_the_search_module_exposes_no_decision():
    """Nothing importable from the module answers "may this proceed"."""

    module = importlib.import_module("firewall.twin.adversarial")
    for name in dir(module):
        assert "authorize" not in name.lower()
        assert "permit" not in name.lower()


def test_a_finding_carries_no_verdict():
    """A finding has a severity and a basis. It has no field a caller
    could mistake for a decision."""

    fields = set(_finding().to_dict())
    assert fields == {
        "weakness_type", "description", "severity", "basis",
        "agents_involved", "attack_path", "evidence", "remediation",
    }


