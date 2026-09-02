"""Performance benchmarks (firewall.benchmarks).

The v2.1 set measures the critical paths of the autonomous defense
layer so bottlenecks are visible and regressions are caught:

* evidence graph append + verify (throughput),
* attack graph build + paths_to (graph scale),
* twin counterfactual (simulation cost),
* defense mesh evaluation over a large agent population,
* a2a authorization with a long delegation chain,
* capability2 policy evaluation.

The v2.4 set measures the authority control plane -- ordinary
authorization, adaptive authorization, revalidation, envelope
calculation, blast-radius analysis, pre-authorization simulation,
delegation traversal, revocation checks, decay application, concurrent
authorization, and the live invariant sweep. Those benchmarks report a
distribution rather than one wall-clock sample; see :func:`_measure` for
the methodology and ``docs/v2.4-performance.md`` for results.

Every benchmark returns a machine-readable report; the suite is
deliberately conservative (small enough to run in CI seconds, large
enough to expose O(n^2) behavior).

Nothing here may weaken a security property to produce a better number.
Where a benchmark needs a cheaper estate it builds a smaller one; it
never disables a gate. The one thing these numbers must not be used for
is deciding to skip a check.
"""

from __future__ import annotations

import json
import statistics
import threading
import time
from typing import Any, Callable, Optional

from firewall.a2a import AgentToAgent
from firewall.aegis.decay import DecaySchedule
from firewall.attackgraph import AttackGraph
from firewall.capability2 import Capability2
from firewall.defense import DefenseMesh
from firewall.evidence_graph import EvidenceGraph, KeyEvidenceSigner
from firewall.ident import IdentityRegistry
from firewall.invariants import (
    check_aegis_state_transitions,
    check_capability_monotonicity,
    check_delegation_monotonicity,
    check_envelope_monotonicity,
    check_revocation_monotonicity,
)
from firewall.network import AgentNetworkGraph
from firewall.network.model import (
    EntityType,
    NetworkEdge,
    NetworkNode,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.sdk import FirewallSDK
from firewall.twin import SecurityTwin


def _timed(fn: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return result, elapsed


def _measure(
    run: Callable[[], Any],
    *,
    name: str,
    operations: int,
    warmup: int = 1,
    repeats: int = 5,
    **details: Any,
) -> dict[str, Any]:
    """Time ``run`` repeatedly and report the distribution, not one sample.

    The methodology, stated here because §14 asks for a reproducible one:

    * ``warmup`` untimed calls first. First-call costs -- lazy imports,
      cold attribute caches, the specializing interpreter warming up --
      are real, but they are startup costs, not per-operation costs, and
      attributing them to the measurement makes every number depend on
      benchmark ordering.
    * ``repeats`` timed calls, reported as **median and p95** rather than
      mean. A mean over a handful of samples on a machine that is also
      running a test suite is a number dominated by whichever sample got
      descheduled; the median survives that and the p95 shows it.
    * ``operations`` is how many security operations one call performs, so
      ``operations_per_second`` is derived from the median rather than from
      a single run.
    * ``time.perf_counter`` throughout: the platform's highest-resolution
      monotonic clock. ``time.time`` on Windows advances in 15.6 ms steps,
      which is coarser than most of these benchmarks measure.

    The spread is part of the result, not noise to be hidden. Where
    ``seconds_p95`` is far above ``seconds_median`` the honest reading is
    that the difference being measured is smaller than the machine's own
    variance -- and a doc that then quotes a precise overhead figure is
    quoting the scheduler.
    """

    for _ in range(max(0, warmup)):
        run()

    samples: list[float] = []
    for _ in range(max(1, repeats)):
        start = time.perf_counter()
        run()
        samples.append(time.perf_counter() - start)

    samples.sort()
    median = statistics.median(samples)
    index = int(round(0.95 * (len(samples) - 1)))
    p95 = samples[min(index, len(samples) - 1)]

    return {
        "name": name,
        "operations": operations,
        "repeats": len(samples),
        "warmup": max(0, warmup),
        "seconds_median": round(median, 6),
        "seconds_min": round(samples[0], 6),
        "seconds_max": round(samples[-1], 6),
        "seconds_p95": round(p95, 6),
        "operations_per_second": (
            round(operations / median, 1) if median else None
        ),
        **details,
    }


def benchmark_evidence_append(
    count: int = 200,
) -> dict[str, Any]:
    graph = EvidenceGraph(signer=KeyEvidenceSigner())

    def run() -> int:
        for i in range(count):
            graph.append(
                "observed" if i % 2 == 0 else "inference",
                f"subject-{i % 10}",
                "event",
                {"i": i},
            )
        return len(graph.events())

    result, elapsed = _timed(run)
    return {
        "name": "evidence_append",
        "events": result,
        "seconds": round(elapsed, 4),
        "events_per_second": round(result / elapsed, 1) if elapsed else None,
    }


def benchmark_evidence_verify(count: int = 200) -> dict[str, Any]:
    graph = EvidenceGraph(signer=KeyEvidenceSigner())
    for i in range(count):
        graph.append("observed", "x", "event", {"i": i})

    _, elapsed = _timed(graph.verify)
    return {
        "name": "evidence_verify",
        "events": count,
        "seconds": round(elapsed, 4),
        "events_per_second": round(count / elapsed, 1) if elapsed else None,
    }


def _large_network(agents: int = 60, caps_per_agent: int = 3) -> AgentNetworkGraph:
    g = AgentNetworkGraph()
    for i in range(agents):
        agent = f"agent-{i}"
        g._nodes[entity_id(EntityType.AGENT, agent)] = NetworkNode(
            entity_id(EntityType.AGENT, agent),
            EntityType.AGENT,
            agent,
            Provenance.OBSERVED,
        )
        for c in range(caps_per_agent):
            cap = f"cap-{i}-{c}"
            g._nodes[entity_id(EntityType.CAPABILITY, cap)] = NetworkNode(
                entity_id(EntityType.CAPABILITY, cap),
                EntityType.CAPABILITY,
                cap,
                Provenance.OBSERVED,
            )
            g._edges.append(
                NetworkEdge(
                    entity_id(EntityType.CAPABILITY, cap),
                    entity_id(EntityType.AGENT, agent),
                    RelationType.ISSUED,
                    Provenance.OBSERVED,
                )
            )
    return g


def benchmark_attack_graph(agents: int = 60) -> dict[str, Any]:
    network = _large_network(agents)

    def build() -> AttackGraph:
        return AttackGraph.from_network(network)

    graph, build_elapsed = _timed(build)

    def paths() -> int:
        return len(graph.paths_to("cap-0-0"))

    _, paths_elapsed = _timed(paths)

    return {
        "name": "attack_graph",
        "agents": agents,
        "nodes": len(graph.nodes()),
        "edges": len(graph.edges()),
        "build_seconds": round(build_elapsed, 4),
        "paths_seconds": round(paths_elapsed, 4),
    }


def benchmark_twin(agents: int = 40) -> dict[str, Any]:
    network = _large_network(agents)
    twin = SecurityTwin.from_network(network)
    twin.snapshot()

    def run() -> str:
        report = twin.compromise("agent-0")
        return report.kind

    result, elapsed = _timed(run)
    return {
        "name": "twin_compromise",
        "agents": agents,
        "seconds": round(elapsed, 4),
        "result": result,
    }


def benchmark_mesh_population(agents: int = 100) -> dict[str, Any]:
    reg = IdentityRegistry()
    for i in range(agents):
        reg.create(f"agent-{i}")
    mesh = DefenseMesh(reg)

    def run() -> int:
        for i in range(agents):
            mesh.evaluate(f"agent-{i}")
        return agents

    result, elapsed = _timed(run)
    return {
        "name": "mesh_evaluate_population",
        "agents": result,
        "seconds": round(elapsed, 4),
        "evaluations_per_second": round(result / elapsed, 1) if elapsed else None,
    }


def benchmark_a2a_chain(depth: int = 30) -> dict[str, Any]:
    reg = IdentityRegistry()
    for i in range(depth + 1):
        reg.create(f"n{i}")
    a2a = AgentToAgent(reg)
    root = a2a.establish(
        initiator="n0", responder="n1",
        permissions={"allowed_actions": ["read"]},
    )
    current = root
    for i in range(2, depth + 1):
        current = a2a.delegate(
            current, responder=f"n{i}",
            permissions={"allowed_actions": ["read"]},
        )

    def run() -> bool:
        return a2a.authorize(
            actor="n0", target=f"n{depth}", action="read"
        ).allowed

    result, elapsed = _timed(run)
    return {
        "name": "a2a_authorize_chain",
        "depth": depth,
        "allowed": result,
        "seconds": round(elapsed, 4),
    }


def benchmark_capability2(iterations: int = 1000) -> dict[str, Any]:
    cap = Capability2(
        "payments.send",
        constraints={
            "resource": "payments",
            "scope": "/prod",
            "action": ["send", "refund"],
            "identity": {"agent_id": "alice"},
            "lineage": {"max_depth": 2},
            "environment": {"env": "prod"},
        },
    )
    request = {
        "resource": "payments",
        "path": "/prod/invoice",
        "action": "send",
        "agent_id": "alice",
        "delegation_depth": 1,
        "env": "prod",
    }

    def run() -> int:
        allowed = 0
        for _ in range(iterations):
            if cap.evaluate(request)[0]:
                allowed += 1
        return allowed

    result, elapsed = _timed(run)
    return {
        "name": "capability2_evaluate",
        "iterations": iterations,
        "allowed": result,
        "seconds": round(elapsed, 4),
        "evaluations_per_second": round(iterations / elapsed, 1) if elapsed else None,
    }


# ======================================================================
# v2.4: the authority control plane
# ======================================================================

KEY_ID = "bench-key"
ACTION = "payments.send"
REQUEST = {"amount": 10}


def _estate(
    *,
    aegis_enabled: bool,
    depth: int = 0,
    ceiling: int = 500,
    track: bool = True,
) -> tuple[FirewallSDK, Any, list[str], Any]:
    """A live estate: one root grant plus ``depth`` delegations.

    Returns ``(sdk, leaf_capability, fingerprints, private_key)``, with
    ``fingerprints`` root-first. The leaf is the capability a caller would
    actually present, so a depth-``n`` estate measures what an agent
    ``n`` delegations deep pays.

    Every grant is registered with Aegis when Aegis is on. An
    unregistered grant measures the *untracked* path through
    ``_gate_aegis``, which is close to free and would understate the
    adaptive cost -- exactly the kind of flattering benchmark §14 is
    asking not to publish.
    """

    sdk = FirewallSDK(aegis_enabled=aegis_enabled)
    private_key = sdk.generate_key(KEY_ID).private_key

    capability = sdk.issue(
        agent="agent-0",
        capability=ACTION,
        private_key=private_key,
        constraints={"amount_max": ceiling},
    )
    fingerprints = [sdk.fingerprint(capability)]

    for level in range(depth):
        capability = sdk.delegate(
            capability,
            private_key,
            delegatee=f"agent-{level + 1}",
            constraints={"amount_max": ceiling},
        ).child
        fingerprints.append(sdk.fingerprint(capability))

    if aegis_enabled and track:
        for index, fingerprint in enumerate(fingerprints):
            sdk.aegis.register(
                fingerprint,
                agent_id=f"agent-{index}",
                capability=ACTION,
            )

    return sdk, capability, fingerprints, private_key


def benchmark_authorize_baseline(count: int = 100) -> dict[str, Any]:
    """``authorize()`` with Aegis off. The reference number.

    Everything adaptive is measured against this, so it deliberately uses
    the same estate shape as :func:`benchmark_authorize_adaptive` and
    differs only in ``aegis_enabled``.
    """

    sdk, capability, _, _ = _estate(aegis_enabled=False)
    try:
        def run() -> None:
            for _ in range(count):
                sdk.authorize(capability, ACTION, REQUEST)

        return _measure(
            run,
            name="authorize_baseline",
            operations=count,
            aegis="disabled",
            outcome="allow",
        )
    finally:
        sdk.close()


def benchmark_authorize_adaptive(count: int = 100) -> dict[str, Any]:
    """``authorize()`` with Aegis on and the grant tracked, allow path.

    The difference from the baseline is the cost of ``_gate_aegis``: two
    store reads (suspension, then restrictions) and, on an allow, one
    ``observe_authorization`` call that may move ``ISSUED -> ACTIVE``.
    """

    sdk, capability, _, _ = _estate(aegis_enabled=True)
    try:
        def run() -> None:
            for _ in range(count):
                sdk.authorize(capability, ACTION, REQUEST)

        return _measure(
            run,
            name="authorize_adaptive",
            operations=count,
            aegis="enabled",
            outcome="allow",
        )
    finally:
        sdk.close()


def benchmark_authorize_restricted(count: int = 100) -> dict[str, Any]:
    """``authorize()`` against a narrowed grant: the adaptive denial path.

    Worth measuring separately, and worth measuring honestly: this path
    is *faster* than an allow, because ``_gate_aegis`` denies before the
    signature check in ``_gate_cryptographic_authority`` runs. A reader
    who assumes adaptive enforcement costs more on every request would be
    wrong in this direction.

    ``aegis_constraint_denied`` is not memoized into refusal state (only
    ``constraint_denied`` and ``policy_denied`` are), so every iteration
    genuinely traverses the gates rather than short-circuiting at
    ``_gate_refusal`` after the first one. ``reason`` is asserted below to
    keep that true if the memoization set ever changes.
    """

    sdk, capability, fingerprints, _ = _estate(aegis_enabled=True)
    try:
        sdk.aegis.narrow(
            fingerprints[-1],
            key="aegis:ceiling",
            reason="benchmark ceiling",
            constraints={"amount_max": 1},
        )
        outcome = sdk.authorize(capability, ACTION, REQUEST)
        if outcome.allowed or not outcome.reason.startswith("aegis_"):
            return {
                "name": "authorize_restricted",
                "error": (
                    "expected an aegis denial, got "
                    f"allowed={outcome.allowed} reason={outcome.reason}"
                ),
            }

        def run() -> None:
            for _ in range(count):
                sdk.authorize(capability, ACTION, REQUEST)

        return _measure(
            run,
            name="authorize_restricted",
            operations=count,
            aegis="enabled",
            outcome="deny",
            reason=outcome.reason,
        )
    finally:
        sdk.close()


def benchmark_envelope(count: int = 100, depth: int = 8) -> dict[str, Any]:
    """``authority_envelope()`` over a depth-``depth`` chain.

    Envelope calculation resolves the chain in the SDK and then folds it
    in ``firewall.aegis.envelope.chain_envelope``, which is pure. Both
    halves scale with chain length, so this is reported alongside
    :func:`benchmark_delegation_traversal` -- if one is linear in depth
    and the other is not, that difference is the interesting finding.
    """

    sdk, capability, _, _ = _estate(aegis_enabled=True, depth=depth)
    try:
        def run() -> None:
            for _ in range(count):
                sdk.authority_envelope(capability)

        envelope = sdk.authority_envelope(capability)
        return _measure(
            run,
            name="envelope",
            operations=count,
            depth=depth,
            bottom=envelope.bottom,
        )
    finally:
        sdk.close()


def benchmark_delegation_traversal(
    count: int = 50,
    depths: tuple[int, ...] = (0, 4, 16),
) -> dict[str, Any]:
    """``authorize()`` at increasing delegation depth.

    Reported as one benchmark with a per-depth breakdown rather than three
    benchmarks, because the number that matters is the *ratio*: a chain
    walk that is linear in depth is expected, and one that is quadratic is
    a denial-of-service lever reachable by anyone who can delegate.

    ``seconds_per_operation_ratio`` divides each depth's median by depth
    0's, so a linear walk shows a ratio that grows roughly with depth and
    a quadratic one shows a ratio that grows much faster.
    """

    per_depth: dict[str, Any] = {}
    baseline: Optional[float] = None

    for depth in depths:
        sdk, capability, _, _ = _estate(aegis_enabled=True, depth=depth)
        try:
            def run(sdk=sdk, capability=capability) -> None:
                for _ in range(count):
                    sdk.authorize(capability, ACTION, REQUEST)

            result = _measure(
                run,
                name=f"delegation_depth_{depth}",
                operations=count,
                depth=depth,
            )
        finally:
            sdk.close()

        median = result["seconds_median"]
        if baseline is None:
            baseline = median or None
        result["ratio_to_depth_0"] = (
            round(median / baseline, 2) if baseline else None
        )
        per_depth[str(depth)] = result

    return {
        "name": "delegation_traversal",
        "depths": list(depths),
        "operations_per_depth": count,
        "by_depth": per_depth,
    }


def benchmark_revocation_check(
    count: int = 200,
    sizes: tuple[int, ...] = (0, 400),
) -> dict[str, Any]:
    """``is_revoked()`` against registries of increasing size.

    Measured at two sizes rather than one, because the claim worth making
    is about *scaling*: a revocation check that degraded with registry size
    would make revocation cost the thing it enforces -- the wrong
    direction, since a system under attack is precisely the one with a
    large revocation set. One size cannot support that claim; the ratio
    can.
    """

    per_size: dict[str, Any] = {}
    baseline: Optional[float] = None

    for size in sizes:
        sdk, capability, _, private_key = _estate(aegis_enabled=False)
        try:
            for index in range(size):
                other = sdk.issue(
                    agent=f"revoked-{index}",
                    capability=ACTION,
                    private_key=private_key,
                    constraints={"amount_max": 1},
                )
                sdk.revoke(other, reason="benchmark fill")

            def run(sdk=sdk, capability=capability) -> None:
                for _ in range(count):
                    sdk.is_revoked(capability)

            result = _measure(
                run,
                name=f"revocation_check_{size}",
                operations=count,
                registry_entries=size,
            )
        finally:
            sdk.close()

        median = result["seconds_median"]
        if baseline is None:
            baseline = median or None
        result["ratio_to_empty_registry"] = (
            round(median / baseline, 2) if baseline else None
        )
        per_size[str(size)] = result

    return {
        "name": "revocation_check",
        "sizes": list(sizes),
        "operations_per_size": count,
        "by_size": per_size,
    }


def benchmark_revalidation(count: int = 50) -> dict[str, Any]:
    """One full revalidation round trip per operation.

    ``begin_revalidation`` drops the grant to zero residual authority,
    then a canonical ``authorize()`` runs, then
    ``observe_authorization`` consumes that outcome and -- only on a
    canonical allow -- moves ``REVALIDATING -> ACTIVE``. That is the single
    edge in the state machine that increases residual authority, and the
    only one requiring evidence, so it is the expensive one by design.

    The measured unit is deliberately the whole trip. Timing
    ``begin_revalidation`` alone would report the cost of giving authority
    up, which is cheap and uninteresting; what an operator needs to budget
    for is the cost of getting it back.
    """

    sdk, capability, fingerprints, _ = _estate(aegis_enabled=True)
    fingerprint = fingerprints[-1]
    try:
        def run() -> None:
            for _ in range(count):
                sdk.aegis.begin_revalidation(
                    fingerprint, reason="benchmark revalidation"
                )
                outcome = sdk.authorize(capability, ACTION, REQUEST)
                sdk.aegis.observe_authorization(fingerprint, outcome)

        run()
        grant = sdk.aegis.grant(fingerprint)
        return _measure(
            run,
            name="revalidation",
            operations=count,
            round_trips=count,
            # ``is not None``, not truthiness: ``AegisGrant.__bool__`` raises
            # on purpose, so that a grant can never be read as a decision.
            final_state=(
                grant.state.value if grant is not None else None
            ),
        )
    finally:
        sdk.close()


def benchmark_blast_radius(
    count: int = 50,
    breadth: int = 60,
) -> dict[str, Any]:
    """Blast radius over a wide tracked lineage.

    The traversal is capped (``MAX_NODES``, ``MAX_DEPTH``,
    ``MAX_FRONTIER``) so a pathological graph cannot turn analysis into a
    denial of service. ``complete`` is reported because a capped run is
    still a valid result -- it is bounded and says so -- and a benchmark
    that silently measured only truncated traversals would be measuring
    the cap, not the analysis.
    """

    sdk, capability, fingerprints, private_key = _estate(
        aegis_enabled=True, depth=2
    )
    try:
        edges: list[tuple[str, str]] = []
        for level in range(1, len(fingerprints)):
            edges.append((fingerprints[level], fingerprints[level - 1]))

        parent = fingerprints[-1]
        for index in range(breadth):
            child = sdk.delegate(
                capability,
                private_key,
                delegatee=f"leaf-{index}",
                constraints={"amount_max": 500},
            ).child
            fingerprint = sdk.fingerprint(child)
            sdk.aegis.register(
                fingerprint, agent_id=f"leaf-{index}", capability=ACTION
            )
            edges.append((fingerprint, parent))

        root = fingerprints[0]

        def run() -> None:
            for _ in range(count):
                sdk.aegis.blast_radius(root, lineage_edges=edges)

        radius = sdk.aegis.blast_radius(root, lineage_edges=edges)
        return _measure(
            run,
            name="blast_radius",
            operations=count,
            lineage_edges=len(edges),
            reach=radius.reach,
            complete=radius.complete,
        )
    finally:
        sdk.close()


def _simulation_report(cases: int = 20):
    """A real ``SimulationReport`` with counted, faithful outcomes.

    Built rather than faked because the preflight simulation stage checks
    the report's own rules: an outcome with no recorded baseline decision is
    not ``counted``, and an uncounted report establishes nothing. A stub
    object would measure the ``UNAVAILABLE`` path -- the cost of declining
    to analyze -- and report it as the cost of analysis.
    """

    from firewall.simulation import RequestCase, RuleSet, simulate

    request_cases = [
        RequestCase(
            case_id=f"case-{index}",
            action=ACTION,
            capability=ACTION,
            root_agent="agent-0",
            root_constraints={"amount_max": 500},
            request=dict(REQUEST),
            baseline_allowed=True,
            baseline_reason="authorized",
        )
        for index in range(cases)
    ]
    before = RuleSet(
        max_delegation_depth=4, trusted_issuers=("trusted-issuer",)
    )
    after = RuleSet(
        max_delegation_depth=2, trusted_issuers=("trusted-issuer",)
    )
    return simulate(request_cases, before, after), before, after, request_cases


def benchmark_simulation(count: int = 5, cases: int = 20) -> dict[str, Any]:
    """``simulate()`` replaying ``cases`` under two rule sets.

    This is the §10 simulator, not the digital twin (see ``twin``). It is
    the expensive analysis path in the system: each case re-signs a
    capability with a simulation key, so cost scales with cases and the
    per-case figure is dominated by asymmetric crypto rather than by policy
    evaluation.

    That expense is the reason the number matters. Simulation is optional
    analysis and cannot grant authority, so an operator needs to know it
    costs roughly a signature per case before putting it on a request path.
    """

    _, before, after, request_cases = _simulation_report(cases)

    from firewall.simulation import simulate

    def run() -> None:
        for _ in range(count):
            simulate(request_cases, before, after)

    report = simulate(request_cases, before, after)
    return _measure(
        run,
        name="simulation",
        operations=count * cases,
        replays=count,
        cases=cases,
        counted_outcomes=len(report.counted_outcomes),
        caveats=len(report.caveats),
    )


def benchmark_preflight(count: int = 100, depth: int = 1) -> dict[str, Any]:
    """The §7 pre-authorization pipeline, all six stages supplied.

    All six are supplied deliberately: a pipeline missing a stage stops at
    ``REVIEW`` and short-circuits, so measuring that would report the cost
    of *declining* to analyze. The estate is small on purpose too --
    ``depth=1`` keeps blast reach inside the bounded-reach threshold, and a
    run that tripped the threshold would be measuring the ``NARROW`` exit
    rather than the full pipeline.

    The recommendation reached is reported, not asserted, and reaching
    ``ALLOW`` here would be a *recommendation*: nothing in this benchmark
    authorizes anything, and ``Preflight.__bool__`` raises to keep the
    result from being read as a decision.
    """

    sdk, capability, fingerprints, _ = _estate(
        aegis_enabled=True, depth=depth
    )
    try:
        envelope = sdk.authority_envelope(capability)
        edges = [
            (fingerprints[level], fingerprints[level - 1])
            for level in range(1, len(fingerprints))
        ]
        blast = sdk.aegis.blast_radius(
            fingerprints[0], lineage_edges=edges
        )
        simulation, _, _, _ = _simulation_report(cases=4)
        now = time.time()

        def analyze():
            return sdk.aegis.preflight(
                ACTION,
                REQUEST,
                fingerprints=fingerprints,
                envelope=envelope,
                now=now,
                chain_resolved=True,
                depth=depth,
                depth_ceiling=depth + 4,
                blast=blast,
                simulation=simulation,
                evidence_findings=(),
            )

        def run() -> None:
            for _ in range(count):
                analyze()

        analysis = analyze()
        return _measure(
            run,
            name="preflight",
            operations=count,
            depth=depth,
            stages=len(analysis.stages),
            impact=analysis.impact.value,
            recommendation=analysis.recommendation.value,
            established=analysis.established,
        )
    finally:
        sdk.close()


def benchmark_decay(count: int = 20, grants: int = 100) -> dict[str, Any]:
    """``apply_decay()`` over ``grants`` scheduled grants.

    Decay is a sweep, so its cost is linear in the tracked population and
    paid by whoever triggers the sweep rather than by a request. Measured
    once past the suspend threshold so every grant has somewhere to move
    on the first pass; later passes are idempotent, which is itself the
    property worth timing -- a sweep that re-did work every call would
    make a large estate expensive to hold.
    """

    sdk = FirewallSDK(aegis_enabled=True)
    private_key = sdk.generate_key(KEY_ID).private_key
    try:
        schedule = DecaySchedule(
            narrow_after=0.0,
            suspend_after=0.0,
            constraints={"amount_max": 1},
            key="aegis:decay",
        )
        for index in range(grants):
            capability = sdk.issue(
                agent=f"decay-{index}",
                capability=ACTION,
                private_key=private_key,
                constraints={"amount_max": 500},
            )
            sdk.aegis.register(
                sdk.fingerprint(capability),
                agent_id=f"decay-{index}",
                capability=ACTION,
                schedule=schedule,
            )

        now = time.time() + 60.0

        def run() -> None:
            for _ in range(count):
                sdk.aegis.apply_decay(now=now)

        record = sdk.aegis.apply_decay(now=now)
        return _measure(
            run,
            name="decay",
            operations=count * grants,
            sweeps=count,
            grants=grants,
            failures=len(getattr(record, "failures", ()) or ()),
        )
    finally:
        sdk.close()


def benchmark_concurrent_authorize(
    threads: int = 8,
    per_thread: int = 40,
) -> dict[str, Any]:
    """``authorize()`` from ``threads`` threads against one shared estate.

    Two numbers come out of this and they answer different questions:

    * ``operations_per_second`` -- aggregate throughput under contention.
      Under CPython's GIL this is not expected to beat the single-threaded
      figure; what matters is that it does not *collapse*, which is what
      lock contention or a serialized store read would look like.
    * ``errors`` -- must be zero. A shared store reached from several
      threads is where a fail-open would appear as an exception escaping
      the gate, so an exception here is a security finding, not a
      performance one.

    Outcomes are counted, not asserted to be allows. Under concurrency the
    honest claim is that every request got *a* canonical decision; pinning
    which one belongs in the concurrency tests, where the interleaving is
    controlled.
    """

    sdk, capability, _, _ = _estate(aegis_enabled=True)
    try:
        errors: list[str] = []
        decisions: list[int] = []
        lock = threading.Lock()

        def worker() -> None:
            allowed = 0
            try:
                for _ in range(per_thread):
                    outcome = sdk.authorize(capability, ACTION, REQUEST)
                    if outcome.allowed:
                        allowed += 1
            except Exception as exc:  # a gate must not raise
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
            with lock:
                decisions.append(allowed)

        def run() -> None:
            decisions.clear()
            pool = [
                threading.Thread(target=worker) for _ in range(threads)
            ]
            for thread in pool:
                thread.start()
            for thread in pool:
                thread.join()

        result = _measure(
            run,
            name="concurrent_authorize",
            operations=threads * per_thread,
            threads=threads,
            per_thread=per_thread,
            errors=errors,
        )
        # Read after the measurement, not as an argument to it: arguments are
        # evaluated before ``_measure`` runs a single thread, so passing
        # ``sum(decisions)`` inline reported the empty list every time.
        result["allowed_last_run"] = sum(decisions)
        result["decisions_last_run"] = len(decisions)
        if errors:
            result["error"] = f"authorize raised under concurrency: {errors[0]}"
        return result
    finally:
        sdk.close()


def benchmark_invariant_sweep(count: int = 10, depth: int = 4) -> dict[str, Any]:
    """The five live-estate invariant checks over a populated estate.

    This is the release gate's per-check cost, and the reason to publish it
    is operational rather than architectural: a sweep cheap enough to run
    per request could be run continuously, and one that is not must be run
    at a checkpoint. The measured figure says which world we are in.

    Any status other than ``violated`` is fine here -- an ``unverifiable``
    check costs what it costs. Whether the checks *hold* is the invariant
    suite's job, not this benchmark's.
    """

    sdk, capability, fingerprints, _ = _estate(
        aegis_enabled=True, depth=depth
    )
    try:
        sdk.authorize(capability, ACTION, REQUEST)
        sdk.aegis.narrow(
            fingerprints[-1],
            key="aegis:ceiling",
            reason="benchmark ceiling",
            constraints={"amount_max": 5},
        )

        checks = (
            check_delegation_monotonicity,
            check_capability_monotonicity,
            check_revocation_monotonicity,
            check_envelope_monotonicity,
            check_aegis_state_transitions,
        )

        def run() -> None:
            for _ in range(count):
                for check in checks:
                    check(sdk)

        statuses = {
            check(sdk).name: check(sdk).status.value for check in checks
        }
        return _measure(
            run,
            name="invariant_sweep",
            operations=count * len(checks),
            sweeps=count,
            checks=len(checks),
            depth=depth,
            statuses=statuses,
        )
    finally:
        sdk.close()


BENCHMARKS: dict[str, Callable[..., dict[str, Any]]] = {
    # v2.1: the autonomous defense layer.
    "evidence_append": benchmark_evidence_append,
    "evidence_verify": benchmark_evidence_verify,
    "attack_graph": benchmark_attack_graph,
    "twin": benchmark_twin,
    "mesh": benchmark_mesh_population,
    "a2a_chain": benchmark_a2a_chain,
    "capability2": benchmark_capability2,
    # v2.4: the authority control plane.
    "authorize_baseline": benchmark_authorize_baseline,
    "authorize_adaptive": benchmark_authorize_adaptive,
    "authorize_restricted": benchmark_authorize_restricted,
    "envelope": benchmark_envelope,
    "delegation_traversal": benchmark_delegation_traversal,
    "revocation_check": benchmark_revocation_check,
    "revalidation": benchmark_revalidation,
    "blast_radius": benchmark_blast_radius,
    "simulation": benchmark_simulation,
    "preflight": benchmark_preflight,
    "decay": benchmark_decay,
    "concurrent_authorize": benchmark_concurrent_authorize,
    "invariant_sweep": benchmark_invariant_sweep,
}

#: Named groups, so ``python -m firewall.benchmarks aegis`` runs the v2.4
#: set without anyone having to remember twelve names. Expanded in
#: :func:`run_benchmarks`; a name that is neither a benchmark nor a group
#: is still reported as unknown rather than skipped.
GROUPS: dict[str, tuple[str, ...]] = {
    "v21": (
        "evidence_append",
        "evidence_verify",
        "attack_graph",
        "twin",
        "mesh",
        "a2a_chain",
        "capability2",
    ),
    "aegis": (
        "authorize_baseline",
        "authorize_adaptive",
        "authorize_restricted",
        "envelope",
        "delegation_traversal",
        "revocation_check",
        "revalidation",
        "blast_radius",
        "simulation",
        "preflight",
        "decay",
        "concurrent_authorize",
        "invariant_sweep",
    ),
}


def _environment() -> dict[str, Any]:
    """What the numbers were produced on.

    A benchmark result without this is not reproducible, and §14 asks for a
    reproducible methodology rather than a leaderboard. ``clock_resolution``
    is included because it bounds what any of these figures can mean:
    ``time.time`` on Windows advances in 15.6 ms steps, so a run that
    reported wall-clock through it would be quantized well above several of
    the measurements here. ``perf_counter`` is what ``_measure`` uses.
    """

    import platform
    import sys

    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "perf_counter_resolution": time.get_clock_info(
            "perf_counter"
        ).resolution,
        "time_resolution": time.get_clock_info("time").resolution,
    }


def run_benchmarks(
    names: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run the requested benchmarks (all by default).

    ``names`` may contain benchmark names or group names from
    :data:`GROUPS`. Anything else is reported as an error entry rather than
    silently dropped -- a typo that quietly ran nothing would look like a
    passing benchmark suite.
    """

    requested = list(names) if names else sorted(BENCHMARKS)

    selected: list[str] = []
    for name in requested:
        expansion = GROUPS.get(name)
        if expansion is None:
            if name not in selected:
                selected.append(name)
            continue
        for member in expansion:
            if member not in selected:
                selected.append(member)

    results: dict[str, Any] = {}
    for name in selected:
        fn = BENCHMARKS.get(name)
        if fn is None:
            results[name] = {"error": f"unknown benchmark: {name}"}
            continue
        try:
            results[name] = fn()
        except Exception as exc:
            results[name] = {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "benchmarks": results,
        "environment": _environment(),
        "generated_at": time.time(),
    }


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry: ``python -m firewall.benchmarks [name|group ...]``.

    Groups are ``v21`` and ``aegis``; with no arguments every benchmark
    runs. Exit status is 1 if any benchmark errored, so this is usable as a
    smoke check as well as a measurement.
    """

    import sys

    names = list(argv or sys.argv[1:]) or None
    report = run_benchmarks(names)
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    failed = [
        name
        for name, result in report["benchmarks"].items()
        if "error" in result
    ]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
