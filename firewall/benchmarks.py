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

The v2.6 set measures the authority epoch: its primitives, the floor it
puts under a request, and -- the number that matters -- the fraction of
requests denied when authorization races a continuous stream of widening
writes. That fraction is the price of the security property, so it is
published rather than described.

The v2.7 set measures the execution-lease path: plain ``authorize()`` as
the reference, then authorize + lease issue, then + continuity
validation, then + the atomic reservation, and the fail-closed denial of
a lease whose authority was revoked in between. Each number is the same
boundary with one more protection layer attached, so the deltas are the
honest cost of keeping authority attached to the act.

The v2.8 set measures the side-effect commit protocol on top of the
execution lease: the durable intent (outbox), the single atomic attempt,
the observed receipt, the full commit, and the recovery/reconciliation
path out of the explicit UNKNOWN state. The recovery row is published
rather than smoothed over, because the UNKNOWN state is the price of
never guessing about an external side effect.

The v2.9 set measures the verification stage between OBSERVED and
COMPLETED: independently checking a recorded provider-evidence claim
with a named authenticator (the cost of establishing that the recorded
claim can be trusted), and the fail-closed refusal of a commit whose
evidence no verifier confirmed. Publishing the refusal path matters too:
the security property has a price, and the price is that a completed
side effect is never guessed.

The v3.0 set measures the security state-commitment layer: the
cost of one coherent-snapshot verification on the allow path, the
cost of one committed state transition (the write-side journal),
and -- the number that matters -- the fraction of requests denied
when a stream of silent store mutations races the boundary. That
fraction is the price of never relying on a security state the
firewall cannot prove is coherent, so it is published rather than
described.

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
from firewall.continuous_auth import MonitoringConfig
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
from firewall.capability import capability_fingerprint
from firewall.state_commit import STATE_INCOHERENT_PREFIX
from firewall.sdk import FirewallSDK
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)
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


# ----------------------------------------------------------------------
# v2.5: the continuous-authorization path, which two security fixes made
# more expensive and which nothing was measuring.
# ----------------------------------------------------------------------


def _continuous_estate(
    *, depth: int = 0, ceiling: int = 500
) -> tuple[FirewallSDK, Any, list[str], Any]:
    """An estate with continuous authorization *and* Aegis wired.

    Both matter for these numbers. With Aegis off, ``_probe_aegis`` returns
    ``UNKNOWN`` after a single ``getattr`` and the snapshot measures a path
    no monitored deployment takes. Periodic revalidation is off because the
    background sweep would time itself into the samples.
    """

    sdk = FirewallSDK(
        aegis_enabled=True,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False
        ),
    )
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

    for index, fingerprint in enumerate(fingerprints):
        sdk.aegis.register(
            fingerprint,
            agent_id=f"agent-{index}",
            capability=ACTION,
        )

    return sdk, capability, fingerprints, private_key


def benchmark_context_snapshot(
    count: int = 100, depth: int = 2
) -> dict[str, Any]:
    """``_capture_snapshot`` and the state probes v2.5 added to it.

    The snapshot is the thing v2.5 changed. It runs on every
    ``authorize_continuous`` and every ``revalidate``, and two fixes -- row
    15's ``aegis_restrictions`` and row 22's ``refusal_state`` -- added a
    probe each. So the per-probe cost is reported alongside the whole, and
    the two v2.5 probes are named in the report rather than left for a
    reader to difference two releases' totals.

    Per-probe figures are measured directly, not inferred by disabling a
    field. Removing a field to time the remainder would mean shipping a
    benchmark that constructs the pre-fix snapshot, and the pre-fix snapshot
    is the defect.
    """

    sdk, capability, fingerprints, _ = _continuous_estate(depth=depth)
    engine = sdk.continuous_auth_engine
    agent = f"agent-{depth}"
    fingerprint = fingerprints[-1]
    try:
        def run() -> None:
            for _ in range(count):
                engine._capture_snapshot(capability, ACTION, REQUEST)

        probes: dict[str, Callable[[], Any]] = {
            "aegis_restrictions": lambda: engine._probe_aegis(fingerprint),
            "refusal_state": lambda: engine._probe_refusal(
                agent, fingerprint
            ),
            "delegation": lambda: engine._probe_delegation(fingerprint),
            "identity": lambda: engine._probe_identity(agent),
            "revoked": lambda: engine._probe_revoked(capability),
            "provenance": lambda: engine._probe_provenance(agent),
        }
        by_probe = {
            label: _measure(
                # Loop inside the timed callable: a single probe is faster
                # than perf_counter's own resolution on some platforms, and
                # timing one call would report the clock.
                lambda probe=probe: [probe() for _ in range(count)],
                name=f"probe_{label}",
                operations=count,
            )
            for label, probe in probes.items()
        }

        snapshot = engine._capture_snapshot(capability, ACTION, REQUEST)
        return _measure(
            run,
            name="context_snapshot",
            operations=count,
            depth=depth,
            # Proof the probes measured above were doing work: an estate
            # where these read UNKNOWN would report a flattering number.
            aegis_restrictions=snapshot.aegis_restrictions,
            refusal_state=snapshot.refusal_state,
            degraded=list(snapshot.degraded_dependencies),
            by_probe={
                label: {
                    "seconds_median": report["seconds_median"],
                    "operations_per_second": report["operations_per_second"],
                }
                for label, report in by_probe.items()
            },
        )
    finally:
        sdk.close()


def benchmark_continuous_authorize(
    count: int = 100, depth: int = 2
) -> dict[str, Any]:
    """``authorize_continuous()`` against plain ``authorize()``.

    The surcharge for turning monitoring on, measured on the same estate in
    the same run rather than by comparing this benchmark's median against
    ``authorize_adaptive``'s from a different process. The decision is
    identical -- ``authorize_continuous`` returns ``authorize()``'s verdict
    -- so everything the difference contains is snapshot and cache work.

    Reported as a ratio as well as two medians, because the ratio is the
    part that survives being run on someone else's machine.
    """

    sdk, capability, fingerprints, _ = _continuous_estate(depth=depth)
    try:
        def run_plain() -> None:
            for _ in range(count):
                sdk.authorize(capability, ACTION, REQUEST)

        def run_monitored() -> None:
            for _ in range(count):
                sdk.authorize_continuous(capability, ACTION, REQUEST)

        plain = _measure(
            run_plain, name="authorize_plain", operations=count
        )
        monitored = _measure(
            run_monitored, name="continuous_authorize", operations=count
        )

        # The verdict is the same object shape from the same boundary; if it
        # ever is not, the surcharge below is comparing two different things.
        verdict = sdk.authorize_continuous(capability, ACTION, REQUEST)
        plain_median = plain["seconds_median"]
        monitored_median = monitored["seconds_median"]
        return {
            **monitored,
            "depth": depth,
            "allowed": verdict.allowed,
            "reason": verdict.reason,
            "plain_seconds_median": plain_median,
            "monitoring_surcharge_seconds": round(
                monitored_median - plain_median, 6
            ),
            "monitoring_surcharge_ratio": (
                round(monitored_median / plain_median, 3)
                if plain_median
                else None
            ),
        }
    finally:
        sdk.close()


def benchmark_continuous_revalidate(
    count: int = 50, depth: int = 2
) -> dict[str, Any]:
    """The two revalidation paths, and the price of a deliberately coarse probe.

    Three loops:

    * **fast path** -- nothing has changed, the digests match, and no
      canonical call is made. The common case, and the reason the digest
      exists.
    * **tolerated change** -- a refusal is latched against a *different*
      action on the same capability, which moves ``refusal_state`` but which
      ``_gate_refusal`` would not deny for the monitored action. So the
      digest says "something changed", the engine routes to ``authorize()``,
      and ``authorize()`` allows. This is the measured cost of
      ``_probe_refusal`` being coarser than the gate it protects -- the
      trade v2.5 made on purpose, priced rather than asserted to be small.
    * **flip control** -- the two refusal-store writes with no revalidation,
      so the loop above can be read without attributing the writes to the
      engine.

    Each iteration of the second loop revalidates twice, once in each
    direction, because a changed revalidation *rewrites* the cached
    snapshot: latch, revalidate, clear, revalidate. Without the second call
    every iteration after the first would silently be a fast path, and the
    benchmark would report the number it was written to disprove.
    """

    sdk, capability, fingerprints, _ = _continuous_estate(depth=depth)
    agent = f"agent-{depth}"
    fingerprint = fingerprints[-1]
    other_action = f"{ACTION}.unmonitored"
    refusals = sdk.refusal_state
    try:
        sdk.authorize_continuous(capability, ACTION, REQUEST)

        def latch() -> None:
            refusals.record(
                agent=agent,
                capability_fingerprint=fingerprint,
                action=other_action,
                request=REQUEST,
                reason="benchmark tolerated change",
            )

        def unlatch() -> None:
            refusals.clear(
                agent=agent,
                capability_fingerprint=fingerprint,
                action=other_action,
                request=REQUEST,
            )

        def run_fast() -> None:
            for _ in range(count):
                sdk.revalidate(capability, ACTION, REQUEST)

        def run_tolerated() -> None:
            for _ in range(count):
                latch()
                sdk.revalidate(capability, ACTION, REQUEST)
                unlatch()
                sdk.revalidate(capability, ACTION, REQUEST)

        def run_flip() -> None:
            for _ in range(count):
                latch()
                unlatch()

        fast = _measure(run_fast, name="revalidate_fast", operations=count)

        # Measured, not assumed: the loop below is only the advertised
        # measurement if the digest really moves and the boundary really
        # still allows. A fast path here would make the tolerated figure a
        # second copy of the one above.
        latch()
        probe = sdk.revalidate(capability, ACTION, REQUEST)
        unlatch()
        sdk.revalidate(capability, ACTION, REQUEST)

        tolerated = _measure(
            run_tolerated, name="revalidate_tolerated", operations=count * 2
        )
        flip = _measure(run_flip, name="refusal_flip", operations=count * 2)

        fast_median = fast["seconds_median"]
        return {
            **fast,
            "name": "continuous_revalidate",
            "depth": depth,
            "tolerated_state_changed": probe.state_changed,
            "tolerated_allowed": probe.revalidated_allowed,
            "tolerated_reason": probe.reason,
            "tolerated_seconds_median": tolerated["seconds_median"],
            "tolerated_operations_per_second": (
                tolerated["operations_per_second"]
            ),
            "flip_seconds_median": flip["seconds_median"],
            # Per revalidation, with the store writes taken back out.
            "coarse_probe_surcharge_seconds": round(
                (tolerated["seconds_median"] - flip["seconds_median"])
                / (count * 2)
                - fast_median / count,
                8,
            ),
        }
    finally:
        sdk.close()


def benchmark_epoch_primitives(count: int = 20000) -> dict[str, Any]:
    """The authority epoch's own operations, in isolation.

    Four figures, because four different call sites pay them:

    * ``sample`` -- one lock acquisition and a three-tuple. ``authorize()``
      takes two of these per request, so twice this is the floor on the
      boundary's v2.6 surcharge.
    * ``covers`` -- the comparison itself, no lock. Once per request.
    * ``widening`` -- the bracket a widening write is wrapped in: two lock
      acquisitions around a body. Paid by operators, not by requests.
    * ``unbound`` -- ``record_widening`` on a store with no epoch. This is
      the pass-through path a standalone store takes, and it is measured
      because a library user constructing a store directly should be able
      to see that the mechanism costs them a ``getattr``.

    ``count`` is large because a single lock acquisition is faster than
    ``perf_counter``'s resolution on Windows; the loop is inside the timed
    callable so what is reported is the operation and not the clock.
    """

    from firewall.authority_epoch import (
        AuthorityEpoch,
        bind_epoch,
        record_widening,
    )

    epoch = AuthorityEpoch()
    first = epoch.sample()
    second = epoch.sample()

    class Bound:
        pass

    bound = Bound()
    bind_epoch(bound, epoch)
    unbound = Bound()

    def sample_run() -> None:
        for _ in range(count):
            epoch.sample()

    def covers_run() -> None:
        for _ in range(count):
            first.covers(second)

    def widening_run() -> None:
        for _ in range(count):
            with record_widening(bound, "benchmark"):
                pass

    def unbound_run() -> None:
        for _ in range(count):
            with record_widening(unbound, "benchmark"):
                pass

    sample = _measure(sample_run, name="epoch_sample", operations=count)
    covers = _measure(covers_run, name="epoch_covers", operations=count)
    widening = _measure(
        widening_run, name="epoch_widening", operations=count
    )
    pass_through = _measure(
        unbound_run, name="epoch_unbound", operations=count
    )

    per_sample = sample["seconds_median"] / count
    per_covers = covers["seconds_median"] / count

    return {
        "name": "epoch_primitives",
        "operations": count,
        "sample_seconds_median": sample["seconds_median"],
        "sample_operations_per_second": sample["operations_per_second"],
        "covers_seconds_median": covers["seconds_median"],
        "covers_operations_per_second": covers["operations_per_second"],
        "widening_seconds_median": widening["seconds_median"],
        "widening_operations_per_second": (
            widening["operations_per_second"]
        ),
        "unbound_seconds_median": pass_through["seconds_median"],
        # Two samples and one comparison: what the boundary added, from
        # the primitives rather than from differencing two releases.
        "per_authorization_floor_seconds": round(
            2 * per_sample + per_covers, 9
        ),
        "widenings_recorded": epoch.sample().finished,
    }


def benchmark_authorize_epoch(count: int = 100) -> dict[str, Any]:
    """``authorize()`` on the shipped path, against the epoch's own cost.

    The comparison a reader wants is "what did v2.6 add to a request", and
    the tempting way to produce it is to build an SDK with the comparison
    disabled and difference the two. That benchmark is not written here for
    the same reason :func:`benchmark_context_snapshot` does not construct a
    pre-v2.5 snapshot: the unprotected boundary is the defect, and shipping
    a supported way to run it would be a second, weaker authorization path
    reachable from a performance module.

    So the surcharge is composed instead. ``epoch_floor_seconds`` is two
    samples plus one comparison, measured directly by
    :func:`benchmark_epoch_primitives`, and ``epoch_share_of_authorize`` is
    that over the measured per-request cost. It is a floor, not the whole:
    binding the stores at construction and carrying ``entry_epoch`` on the
    context cost something too, and neither is separable from the request
    it happens inside.
    """

    from firewall.authority_epoch import AuthorityEpoch

    sdk, capability, _, _ = _estate(aegis_enabled=True)
    try:
        def run() -> None:
            for _ in range(count):
                sdk.authorize(capability, ACTION, REQUEST)

        result = _measure(
            run,
            name="authorize_epoch",
            operations=count,
            aegis="enabled",
            outcome="allow",
        )

        epoch = AuthorityEpoch()
        probe = epoch.sample()

        def floor_run() -> None:
            for _ in range(count):
                epoch.sample().covers(probe)
                epoch.sample()

        floor = _measure(
            floor_run, name="epoch_floor", operations=count
        )

        per_request = result["seconds_median"] / count
        per_floor = floor["seconds_median"] / count

        result["epoch_floor_seconds"] = round(per_floor, 9)
        result["per_authorization_seconds"] = round(per_request, 9)
        result["epoch_share_of_authorize"] = (
            round(per_floor / per_request, 6) if per_request else None
        )
        # Confirms the measured path is the protected one. A run that
        # reported a number with the comparison somehow absent would be
        # measuring pre-v2.6 code and saying nothing about what ships.
        result["epoch_bound"] = (
            isinstance(
                getattr(sdk, "authority_epoch", None), AuthorityEpoch
            )
        )
        return result
    finally:
        sdk.close()


def benchmark_authorize_under_widening(
    threads: int = 8,
    per_thread: int = 40,
) -> dict[str, Any]:
    """Authorization under a continuous stream of widening writes.

    This is the benchmark that measures what v2.6 actually costs, and the
    cost is not latency. Eight threads authorize while one thread widens in
    a loop, so most requests have a widening interval overlapping their
    reads -- and the boundary is supposed to deny those. The number to read
    is ``denied_fraction``, not throughput.

    That fraction is a *worst case by construction*, not a deployment
    estimate. A real operator does not clear the refusal ledger in a loop;
    the writer here holds a widening open essentially all the time, which
    is the shape that maximizes overlap. Quoting it as an expected denial
    rate would be quoting this benchmark's writer, not any real workload.

    ``errors`` must be zero. An exception escaping the boundary under
    contention would be a fail-open, and the epoch comparison sits at the
    end of the chain where a raise would skip the verdict entirely -- so
    this is a security assertion that happens to live in a performance
    module. Denials are counted rather than treated as failures: a denial
    is the mechanism working.

    Denials are partitioned into epoch and non-epoch, and any non-epoch
    reason is *named* in the output rather than left as a count. The first
    version of this benchmark classified on one prefix and reported 43
    unexplained denials per run; they were all
    ``widening_in_flight_at_entry``, which is an epoch denial in the second
    of its three forms. Classifying against
    :data:`~firewall.authority_epoch.EPOCH_DIVERGENCE_PREFIXES` and naming
    the remainder is what makes that mistake visible instead of plausible.
    """

    from firewall.authority_epoch import is_epoch_denial

    sdk, capability, _, _ = _estate(aegis_enabled=True)
    try:
        errors: list[str] = []
        allowed: list[int] = []
        epoch_denials: list[int] = []
        other: list[str] = []
        lock = threading.Lock()
        stop = threading.Event()

        def worker() -> None:
            mine_allowed = 0
            mine_epoch = 0
            mine_other: list[str] = []
            try:
                for _ in range(per_thread):
                    outcome = sdk.authorize(capability, ACTION, REQUEST)
                    if outcome.allowed:
                        mine_allowed += 1
                    elif is_epoch_denial(outcome.reason):
                        mine_epoch += 1
                    else:
                        mine_other.append(outcome.reason.split(":")[0])
            except Exception as exc:  # a gate must not raise
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
            with lock:
                allowed.append(mine_allowed)
                epoch_denials.append(mine_epoch)
                other.extend(mine_other)

        def widener() -> None:
            try:
                while not stop.is_set():
                    sdk.refusal_state.clear_all()
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(f"widener {type(exc).__name__}: {exc}")

        def run() -> None:
            allowed.clear()
            epoch_denials.clear()
            other.clear()
            stop.clear()
            writer = threading.Thread(target=widener, daemon=True)
            writer.start()
            pool = [
                threading.Thread(target=worker) for _ in range(threads)
            ]
            for thread in pool:
                thread.start()
            for thread in pool:
                thread.join()
            stop.set()
            writer.join(10)

        result = _measure(
            run,
            name="authorize_under_widening",
            operations=threads * per_thread,
            threads=threads,
            per_thread=per_thread,
            errors=errors,
        )

        # Read after the measurement: _measure evaluates its arguments
        # before running anything, so an inline sum reports an empty list.
        total = sum(allowed) + sum(epoch_denials) + len(other)
        result["allowed_last_run"] = sum(allowed)
        result["epoch_denials_last_run"] = sum(epoch_denials)
        result["other_denials_last_run"] = len(other)
        result["other_denial_reasons"] = sorted(set(other))
        result["decisions_last_run"] = total
        result["denied_fraction"] = (
            round((total - sum(allowed)) / total, 4) if total else None
        )
        result["widenings_recorded"] = sdk.authority_epoch.sample().finished
        if total != threads * per_thread:
            result["error"] = (
                f"{total} decisions from {threads * per_thread} requests: "
                "a request neither allowed nor denied"
            )
        if errors:
            result["error"] = (
                f"authorize raised under a concurrent widening: {errors[0]}"
            )
        return result
    finally:
        sdk.close()


def benchmark_epoch_contention(
    threads: int = 8,
    per_thread: int = 5000,
) -> dict[str, Any]:
    """The epoch lock under the load the boundary puts on it.

    One lock, taken twice per authorization and twice per widening write,
    is a plausible place for a global bottleneck to appear -- and it would
    appear as a throughput collapse rather than as a failure, which is why
    it is measured rather than argued about.

    The lock is a leaf: nothing is called while it is held, and
    ``widening()`` releases it before yielding to the write body. So
    aggregate sampling throughput should stay in the same order as the
    single-threaded figure from :func:`benchmark_epoch_primitives` rather
    than degrading with thread count. ``monotonic`` is checked because a
    torn read would be a correctness bug this benchmark is in the right
    position to notice: a sampler must never see the finished count go
    backwards.
    """

    from firewall.authority_epoch import AuthorityEpoch

    epoch = AuthorityEpoch()
    regressions: list[str] = []
    lock = threading.Lock()
    stop = threading.Event()

    def sampler() -> None:
        highest = -1
        try:
            for _ in range(per_thread):
                finished = epoch.sample().finished
                if finished < highest:
                    with lock:
                        regressions.append(
                            f"{finished} after {highest}"
                        )
                highest = max(highest, finished)
        except Exception as exc:  # noqa: BLE001
            with lock:
                regressions.append(f"{type(exc).__name__}: {exc}")

    def widener() -> None:
        while not stop.is_set():
            with epoch.widening("contention"):
                pass

    def run() -> None:
        stop.clear()
        writer = threading.Thread(target=widener, daemon=True)
        writer.start()
        pool = [threading.Thread(target=sampler) for _ in range(threads)]
        for thread in pool:
            thread.start()
        for thread in pool:
            thread.join()
        stop.set()
        writer.join(10)

    result = _measure(
        run,
        name="epoch_contention",
        operations=threads * per_thread,
        repeats=3,
        threads=threads,
        per_thread=per_thread,
    )
    result["monotonic"] = not regressions
    result["widenings_recorded"] = epoch.sample().finished
    if regressions:
        result["error"] = (
            f"a sampler saw the finished count regress: {regressions[0]}"
        )
    return result


# ======================================================================
# v2.7: the execution-lease path -- what continuity costs
# ======================================================================
#
# The four numbers measure the same security boundary with increasing
# amounts of the v2.7 guarantee attached. Nothing here is measured
# against an intentionally weaker path: the reference (execution_
# authorize_only) is the v2.6 boundary itself, and each further benchmark
# adds one protection layer on top of it, so the deltas are the honest
# price of "an allow cannot be used once the state it rested on stops
# holding".

EXECUTION_KEY_ID = "v27-bench-key"
EXECUTION_ACTION = "payments.send"
EXECUTION_REQUEST = {"amount": 10}


def _execution_estate() -> tuple[FirewallSDK, Any]:
    """One grant on a fresh SDK, Aegis off: the v2.7 reference estate."""

    sdk = FirewallSDK()
    private_key = sdk.generate_key(EXECUTION_KEY_ID).private_key
    capability = sdk.issue(
        agent="agent-0",
        capability=EXECUTION_ACTION,
        private_key=private_key,
        constraints={"amount_max": 500},
    )
    return sdk, capability


def benchmark_execution_authorize_only(count: int = 100) -> dict[str, Any]:
    """``authorize()`` alone: the boundary the lease extends.

    This is the reference, deliberately the *same* estate shape as the
    other three so the cost of each added layer is the delta between
    otherwise identical numbers.
    """

    sdk, capability = _execution_estate()
    try:
        def run() -> None:
            for _ in range(count):
                result = sdk.authorize(
                    capability, EXECUTION_ACTION, EXECUTION_REQUEST
                )
                if not result.allowed:
                    raise AssertionError(
                        f"reference authorize denied: {result.reason}"
                    )

        return _measure(
            run,
            name="execution_authorize_only",
            operations=count,
            layer="authorize",
        )
    finally:
        sdk.close()


def benchmark_execution_issue(count: int = 50) -> dict[str, Any]:
    """``authorize_execution``: authorize plus the recorded continuation.

    Adds to the reference the outer epoch window, the request digest, the
    delegation-chain fingerprint, the policy-version read and one lease
    store write. The estate is shared and each operation issues a fresh
    lease against the same grant -- the shape a caller issuing many
    executions under one standing authorization would hit.
    """

    sdk, capability = _execution_estate()
    try:
        def run() -> None:
            for _ in range(count):
                outcome = sdk.authorize_execution(
                    capability, EXECUTION_ACTION, EXECUTION_REQUEST
                )
                if not outcome.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {outcome.reason}"
                    )

        return _measure(
            run,
            name="execution_issue",
            operations=count,
            layer="authorize+lease",
            leases_outstanding=count,
        )
    finally:
        sdk.close()


def benchmark_execution_validate(count: int = 100) -> dict[str, Any]:
    """The deny-only continuity re-establishment, isolated.

    One lease is issued and the full live-state validation that every
    progression performs is run repeatedly against it -- revocation,
    issuer trust, signature, time, lineage, policy version, epoch, Aegis,
    risk. This is the check the reservation adds on top of the issue; it
    is measured alone so the reservation number below is the sum of two
    known parts rather than one uninterpretable total.
    """

    sdk, capability = _execution_estate()
    try:
        issued = sdk.authorize_execution(
            capability, EXECUTION_ACTION, EXECUTION_REQUEST
        )
        if not issued.allowed:
            raise AssertionError(f"authorize_execution refused: {issued.reason}")
        record = sdk.execution_leases.get(issued.lease.lease_id)
        lease = issued.lease

        def run() -> int:
            checked = 0
            for _ in range(count):
                ok, reason = sdk._continuity_failure(
                    lease,
                    record,
                    capability,
                    EXECUTION_ACTION,
                    EXECUTION_REQUEST,
                )
                if not ok:
                    raise AssertionError(
                        f"continuity validation refused: {reason}"
                    )
                checked += 1
            return checked

        return _measure(
            run,
            name="execution_validate",
            operations=count,
            layer="authorize+lease+validation",
        )
    finally:
        sdk.close()


_EXECUTION_RESERVE_SEQ = [0]


def benchmark_execution_reserve(count: int = 50) -> dict[str, Any]:
    """The full recorded progression up to the reservation.

    Per operation: authorize, issue the lease, re-establish the authority
    basis, and atomically reserve the lease against an execution identity
    -- the exact point past which the caller holds an exclusive, recorded
    right to start. This is the number an executor's hot path pays.

    Each reservation uses a fresh execution identity (a monotonic counter
    shared across warmup and timed repeats), because a reserved lease is
    live until it is completed or aborted and an identity names one live
    execution. Reusing an identity would measure the refusal path, not
    the reservation path.
    """

    sdk, capability = _execution_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EXECUTION_ACTION, EXECUTION_REQUEST
                )
                if not issued.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {issued.reason}"
                    )
                _EXECUTION_RESERVE_SEQ[0] += 1
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EXECUTION_ACTION,
                    EXECUTION_REQUEST,
                    execution_id=f"bench-exec-{_EXECUTION_RESERVE_SEQ[0]}",
                )
                if not reserved.allowed:
                    raise AssertionError(
                        f"reserve refused: {reserved.reason}"
                    )

        return _measure(
            run,
            name="execution_reserve",
            operations=count,
            layer="authorize+lease+validation+reservation",
        )
    finally:
        sdk.close()


def benchmark_execution_denied(count: int = 20) -> dict[str, Any]:
    """A lease that lost its authority, refused at the reservation.

    The negative control, measured honestly rather than asserted away.
    Each operation builds a fresh grant, authorizes it, revokes it, and
    then asks to reserve the lease it already issued: the reservation is
    a terminal refusal that re-runs the full continuity validation and
    writes the explicit failure state. Revocation is permanent, so a
    fresh grant per operation is the only way to measure the denial path
    rather than the already-terminal fast path -- and the number that
    results is the honest per-action price of fail-closed.
    """

    sdk, _ = _execution_estate()
    _EXECUTION_RESERVE_SEQ[0] += 1000
    try:
        def run() -> int:
            refused = 0
            for _ in range(count):
                _EXECUTION_RESERVE_SEQ[0] += 1
                private_key = sdk.generate_key(
                    f"v27-denied-{_EXECUTION_RESERVE_SEQ[0]}"
                ).private_key
                capability = sdk.issue(
                    agent="agent-0",
                    capability=EXECUTION_ACTION,
                    private_key=private_key,
                    constraints={"amount_max": 500},
                )
                issued = sdk.authorize_execution(
                    capability, EXECUTION_ACTION, EXECUTION_REQUEST
                )
                if not issued.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {issued.reason}"
                    )
                sdk.revoke(capability, reason="benchmark")
                _EXECUTION_RESERVE_SEQ[0] += 1
                outcome = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EXECUTION_ACTION,
                    EXECUTION_REQUEST,
                    execution_id=f"bench-denied-{_EXECUTION_RESERVE_SEQ[0]}",
                )
                if outcome.allowed:
                    raise AssertionError(
                        "a revoked grant reserved successfully"
                    )
                refused += 1
            return refused

        return _measure(
            run,
            name="execution_denied",
            operations=count,
            layer="authorize+lease+revoke+reservation",
            outcome="deny",
        )
    finally:
        sdk.close()




from firewall.effect import (
    EffectOutcome,
    ReceiptKind,
)
from firewall.execution_lease import (
    ExecutionState,
)

# ======================================================================
# v2.8: the side-effect commit protocol -- what making the boundary
# explicit, attestable, idempotent and recoverable costs
# ======================================================================
#
# The v2.7 numbers end at the reservation. v2.8 measures the layers on
# top of the recorded execution: recording the durable intent (outbox),
# the single atomic attempt, the observed receipt, the commit, and the
# recovery/reconciliation path. Each number is the same boundary with one
# more protection layer attached, so the deltas are the honest price of
# "a side effect is never represented as completed unless the protocol
# established what authority existed, what attempt occurred, and what
# completion evidence was observed". The recovery row publishes the cost
# of the explicit UNKNOWN state instead of smoothing it over.

EFFECT_ACTION = EXECUTION_ACTION
EFFECT_REQUEST = dict(EXECUTION_REQUEST)
EFFECT_PAYLOAD = {"to": "bench-account", "amount": 10}
EFFECT_TYPE = "transfer"
EFFECT_SEQ = [0]


def _effect_estate() -> tuple[FirewallSDK, Any]:
    """One grant on a fresh SDK, Aegis off: the v2.8 reference estate."""

    sdk = FirewallSDK()
    private_key = sdk.generate_key(EXECUTION_KEY_ID).private_key
    capability = sdk.issue(
        agent="agent-0",
        capability=EFFECT_ACTION,
        private_key=private_key,
        constraints={"amount_max": 500},
    )
    return sdk, capability


def _fresh_execution_id() -> str:
    EFFECT_SEQ[0] += 1
    return f"bench-effect-{EFFECT_SEQ[0]}"


def _effect_key() -> str:
    EFFECT_SEQ[0] += 1
    return f"key-{EFFECT_SEQ[0]}"


def benchmark_effect_authorize(count: int = 100) -> dict[str, Any]:
    """``authorize()`` alone: the v2.8 reference layer."""

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                result = sdk.authorize(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                if not result.allowed:
                    raise AssertionError(
                        f"reference authorize denied: {result.reason}"
                    )

        return _measure(
            run,
            name="effect_authorize",
            operations=count,
            layer="authorize",
        )
    finally:
        sdk.close()


def benchmark_effect_lease(count: int = 50) -> dict[str, Any]:
    """``authorize_execution``: authorize plus the recorded lease."""

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                outcome = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                if not outcome.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {outcome.reason}"
                    )

        return _measure(
            run,
            name="effect_lease",
            operations=count,
            layer="authorize+lease",
        )
    finally:
        sdk.close()


def benchmark_effect_intent(count: int = 20) -> dict[str, Any]:
    """The full recorded progression up to the durable intent (outbox).

    Per operation: authorize, issue, reserve, start, then prepare -- the
    intent row is written only after the execution's authority basis is
    re-established, which is what makes the outbox a continuation of
    authority rather than a second decision.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                if not issued.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {issued.reason}"
                    )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                if not reserved.allowed:
                    raise AssertionError(
                        f"reserve refused: {reserved.reason}"
                    )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                if not started.allowed:
                    raise AssertionError(
                        f"start refused: {started.reason}"
                    )
                prepared = sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=_effect_key(),
                )
                if not prepared.allowed:
                    raise AssertionError(
                        f"prepare refused: {prepared.reason}"
                    )

        return _measure(
            run,
            name="effect_intent",
            operations=count,
            layer="authorize+lease+reserve+start+intent",
        )
    finally:
        sdk.close()


def benchmark_effect_attempt(count: int = 20) -> dict[str, Any]:
    """... plus the single atomic attempt: the boundary crossing.

    Adds to ``effect_intent`` one atomic ``INTENT_RECORDED ->
    ATTEMPT_STARTED`` compare-and-set, which is the last gate before the
    external request is authorized.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                if not issued.allowed:
                    raise AssertionError(
                        f"authorize_execution refused: {issued.reason}"
                    )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                prepared = sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if not prepared.allowed:
                    raise AssertionError(
                        f"prepare refused: {prepared.reason}"
                    )
                attempted = sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if not attempted.allowed:
                    raise AssertionError(
                        f"attempt refused: {attempted.reason}"
                    )

        return _measure(
            run,
            name="effect_attempt",
            operations=count,
            layer="authorize+...+intent+attempt",
        )
    finally:
        sdk.close()


def benchmark_effect_receipt(count: int = 20) -> dict[str, Any]:
    """... plus recording the observed success receipt.

    Adds to ``effect_attempt`` the three-way outcome receipt under
    currently valid authority -- the observation that makes the side
    effect attestable.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                attempted = sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if not attempted.allowed:
                    raise AssertionError(
                        f"attempt refused: {attempted.reason}"
                    )
                receipt = sdk.record_effect_receipt(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    observed_outcome=EffectOutcome.SUCCEEDED,
                    evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
                    external_request_id="bench-ext",
                )
                if not receipt.allowed:
                    raise AssertionError(
                        f"receipt refused: {receipt.reason}"
                    )

        return _measure(
            run,
            name="effect_receipt",
            operations=count,
            layer="authorize+...+attempt+receipt",
        )
    finally:
        sdk.close()


def _benchmark_authenticator(evidence: Any) -> VerifierVerdict:
    """Named verifier used by the effect_commit benchmark.

    Provider-labelled evidence is only confirmed by a verifier the
    deployment wired; the benchmark measures the full v2.9 verified
    chain, so it supplies one.
    """

    return VerifierVerdict(
        outcome=VerificationOutcome.VERIFIED,
        method="benchmark-authenticator",
        note="benchmark authenticator confirms the recorded provider "
        "status",
    )


def benchmark_effect_commit(count: int = 20) -> dict[str, Any]:
    """The full protocol to a clean COMMIT (COMPLETED).

    Adds to ``effect_receipt`` the commit: the completion evidence
    exists, so the execution is recorded COMPLETED. This is the number an
    executor that adopted the protocol pays per real-world action.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                receipt = sdk.record_effect_receipt(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    observed_outcome=EffectOutcome.SUCCEEDED,
                    evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
                )
                if not receipt.allowed:
                    raise AssertionError(
                        f"receipt refused: {receipt.reason}"
                    )
                committed = sdk.commit_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    verifier=_benchmark_authenticator,
                    method="benchmark-authenticator",
                )
                if not committed.allowed:
                    raise AssertionError(
                        f"commit refused: {committed.reason}"
                    )

        return _measure(
            run,
            name="effect_commit",
            operations=count,
            layer="authorize+...+receipt+commit",
        )
    finally:
        sdk.close()


def benchmark_effect_reconcile(count: int = 20) -> dict[str, Any]:
    """The recovery path: a timeout left UNKNOWN, then reconciled.

    Each operation drives the protocol to an ATTEMPT_STARTED row, records
    the three-way UNKNOWN (the honest state after a timeout), and then
    performs the explicit reconciliation that confirms success against
    the external status. This is what a crash after transmission costs to
    recover -- published rather than smoothed over, because the UNKNOWN
    state is the price of never guessing.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                attempted = sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if not attempted.allowed:
                    raise AssertionError(
                        f"attempt refused: {attempted.reason}"
                    )
                unknown = sdk.record_effect_receipt(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    observed_outcome=EffectOutcome.UNKNOWN,
                    evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
                    note="benchmark timeout",
                )
                if not unknown.allowed:
                    raise AssertionError(
                        f"unknown receipt refused: {unknown.reason}"
                    )
                reconciled = sdk.reconcile_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    resolution=EffectOutcome.SUCCEEDED,
                    evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
                    external_request_id="bench-ext-recover",
                )
                if not reconciled.allowed:
                    raise AssertionError(
                        f"reconcile refused: {reconciled.reason}"
                    )

        return _measure(
            run,
            name="effect_reconcile",
            operations=count,
            layer="authorize+...+attempt+unknown+reconcile",
        )
    finally:
        sdk.close()


def benchmark_effect_verify(count: int = 20) -> dict[str, Any]:
    """The verification stage (v2.9): OBSERVED -> VERIFIED.

    Adds to ``effect_receipt`` the verification: the recorded claim
    (provider evidence, external correlation id) is given to the named
    authenticator and a VERIFIED claim is journaled. This is the cost of
    establishing that the recorded claim can be trusted, measured apart
    from the receipt so the delta is the honest price of the v2.9 stage.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                attempted = sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if not attempted.allowed:
                    raise AssertionError(
                        f"attempt refused: {attempted.reason}"
                    )
                receipt = sdk.record_effect_receipt(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    observed_outcome=EffectOutcome.SUCCEEDED,
                    evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
                    external_request_id="bench-ext-verify",
                )
                if not receipt.allowed:
                    raise AssertionError(
                        f"receipt refused: {receipt.reason}"
                    )
                verified = sdk.verify_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    verifier=_benchmark_authenticator,
                    method="benchmark-authenticator",
                )
                if not verified.allowed:
                    raise AssertionError(
                        f"verify refused: {verified.reason}"
                    )

        return _measure(
            run,
            name="effect_verify",
            operations=count,
            layer="authorize+...+receipt+verify",
        )
    finally:
        sdk.close()


def benchmark_effect_unverified_commit(count: int = 20) -> dict[str, Any]:
    """The fail-closed refusal of the verified chain (v2.9).

    Measures a refused COMMIT: the recorded claim is provider evidence
    with no named authenticator, so the structural verifier cannot
    confirm it and the completion gate refuses. The refusal row is
    published rather than smoothed over, because the security property
    has a price -- and the price is that a completed side effect is never
    guessed.
    """

    sdk, capability = _effect_estate()
    try:
        def run() -> None:
            for _ in range(count):
                issued = sdk.authorize_execution(
                    capability, EFFECT_ACTION, EFFECT_REQUEST
                )
                reserved = sdk.reserve_execution(
                    issued.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    execution_id=_fresh_execution_id(),
                )
                started = sdk.start_execution(
                    reserved.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                )
                key = _effect_key()
                sdk.prepare_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                sdk.attempt_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                receipt = sdk.record_effect_receipt(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                    observed_outcome=EffectOutcome.SUCCEEDED,
                    evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
                )
                if not receipt.allowed:
                    raise AssertionError(
                        f"receipt refused: {receipt.reason}"
                    )
                committed = sdk.commit_effect(
                    started.lease,
                    capability,
                    EFFECT_ACTION,
                    EFFECT_REQUEST,
                    effect=dict(EFFECT_PAYLOAD),
                    effect_type=EFFECT_TYPE,
                    idempotency_key=key,
                )
                if committed.allowed:
                    raise AssertionError(
                        "provider evidence committed without a named "
                        "authenticator"
                    )

        return _measure(
            run,
            name="effect_unverified_commit",
            operations=count,
            layer="authorize+...+receipt+refused-commit",
        )
    finally:
        sdk.close()


# ======================================================================
# v3.0: the security state-commitment layer -- what proving the state
# coherent costs
# ======================================================================
#
# The v3.0 guarantee is that no authorization relies on a security
# state the firewall cannot prove is coherent. That proof is paid on
# two sides: the ALLOW path verifies the live canonical digest against
# the hash-chained commitment head once per allow, and every
# legitimate in-domain write ends by committing the resulting state to
# the chain. Both are measured here, plus the number an operator
# actually needs -- how often requests are refused while the stores
# are being silently mutated.
STATE_COMMIT_KEY = "v3-bench-key"
STATE_COMMIT_ACTION = "payments.send"
STATE_COMMIT_REQUEST = {"amount": 10}


def _state_commit_estate() -> tuple[FirewallSDK, Any]:
    """One grant on a fresh SDK: the v3.0 reference estate."""

    sdk = FirewallSDK()
    private_key = sdk.generate_key(STATE_COMMIT_KEY).private_key
    capability = sdk.issue(
        agent="agent-0",
        capability=STATE_COMMIT_ACTION,
        private_key=private_key,
        constraints={"amount_max": 500},
    )
    return sdk, capability


def benchmark_state_commit_authorize(count: int = 100) -> dict[str, Any]:
    """``authorize()`` on the shipped v3.0 path: allow with proof.

    The reference number an operator diffs against the v2.6 epoch
    figure. Every allow now ends by verifying the live canonical
    digest of the in-domain stores against the chain head -- one
    digest of revocation plus issuer trust plus lineage plus depth,
    compared under the journal lock. The measured unit is the whole
    shipped request, so this is what a v3.0 deployment pays.
    """

    sdk, capability = _state_commit_estate()
    try:
        def run() -> None:
            for _ in range(count):
                result = sdk.authorize(
                    capability, STATE_COMMIT_ACTION, STATE_COMMIT_REQUEST
                )
                if not result.allowed:
                    raise AssertionError(
                        f"authorize denied: {result.reason}"
                    )

        return _measure(
            run,
            name="state_commit_authorize",
            operations=count,
            outcome="allow",
            chain_height=sdk.state_commit.height(),
            components=len(sdk.state_commit.names()),
        )
    finally:
        sdk.close()


def benchmark_state_commit_transition(count: int = 50) -> dict[str, Any]:
    """One committed in-domain state transition, write side.

    Per operation: revoke a fresh capability through the declared
    write path, so the journal brackets the mutation, re-reads the
    whole canonical state and appends a linked, state-anchored
    commitment. Paid by operators and revokers, never by requests;
    the number an operator needs is how much committing a revocation
    costs per revocation.
    """

    sdk, capability = _state_commit_estate()
    private_key = sdk.keys.active().private_key
    try:
        def run() -> None:
            for _ in range(count):
                victim = sdk.issue(
                    agent="agent-0",
                    capability=STATE_COMMIT_ACTION,
                    private_key=private_key,
                    constraints={"amount_max": 1},
                )
                sdk.revoke(victim, reason="benchmark")

        start_height = sdk.state_commit.height()
        result = _measure(
            run,
            name="state_commit_transition",
            operations=count,
            outcome="committed",
        )
        result["links_appended"] = (
            sdk.state_commit.height() - start_height
        )
        return result
    finally:
        sdk.close()


def benchmark_state_commit_tamper(
    threads: int = 8,
    per_thread: int = 40,
) -> dict[str, Any]:
    """Authorization under a stream of silent store mutations.

    The v3.0 analogue of :func:`benchmark_authorize_under_widening`.
    Eight threads authorize while one thread silently forgets
    revocations directly in the registry dict -- the one class of
    attack the epoch counter cannot see, because no widening write
    moves. The number to read is ``denied_fraction``, and ``errors``
    must be zero. Requests that were not refused either completed
    before the mutation landed or were decided against state that
    still matched the chain head at their commit instant -- that is
    the linearization the mechanism provides.

    ``denial_reasons`` names every refusal so a reader can see the
    coherence denials rather than trusting a count.
    """

    sdk, capability = _state_commit_estate()
    try:
        return _tamper_run(sdk, capability, threads, per_thread)
    finally:
        sdk.close()


def _tamper_run(sdk, capability, threads, per_thread) -> dict[str, Any]:
    """The measured body of the tamper benchmark."""
    private_key = sdk.keys.active().private_key
    victims = []
    for index in range(64):
        victims.append(
            sdk.issue(
                agent="agent-0",
                capability=STATE_COMMIT_ACTION,
                private_key=private_key,
                constraints={"amount_max": 1},
            )
        )
        sdk.revoke(victims[-1], reason="benchmark")

    errors: list[str] = []
    allowed: list[int] = []
    incoherent: list[int] = []
    other: list[str] = []
    lock = threading.Lock()
    stop = threading.Event()
    cursor = [0]

    def worker() -> None:
        mine_allowed = 0
        mine_incoherent = 0
        mine_other: list[str] = []
        try:
            for _ in range(per_thread):
                outcome = sdk.authorize(
                    capability, STATE_COMMIT_ACTION, STATE_COMMIT_REQUEST
                )
                if outcome.allowed:
                    mine_allowed += 1
                elif outcome.reason.startswith(STATE_INCOHERENT_PREFIX):
                    mine_incoherent += 1
                else:
                    mine_other.append(outcome.reason.split(":")[0])
        except Exception as exc:  # a gate must not raise
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")
        with lock:
            allowed.append(mine_allowed)
            incoherent.append(mine_incoherent)
            other.extend(mine_other)

    def tamperer() -> None:
        try:
            while not stop.is_set():
                index = cursor[0] % len(victims)
                cursor[0] += 1
                victim = victims[index]
                fp = capability_fingerprint(victim)
                # The silent mutation: forget a revocation with no
                # declared write path, so no commitment is written.
                sdk.revocation._records.pop(fp, None)
                # Then heal through the legitimate path, so the
                # oscillation is what is measured: a request racing
                # the open window is refused, and one landing after
                # the re-commit is allowed. A tamperer that only
                # ever drifted the state would report a denial
                # fraction of 1.0 that says nothing about the
                # mechanism.
                try:
                    sdk.revoke(victim, reason="benchmark heal")
                except Exception:  # already re-revoked by a racing
                    pass  # tamperer; the committed state is intact
                # Give the workers a committed window to land in
                # between tamper cycles, so the measured fraction is
                # the price of the open window rather than the price
                # of a tamperer that never lets the state settle.
                time.sleep(0.002)
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(f"tamperer {type(exc).__name__}: {exc}")

    def run() -> None:
        allowed.clear()
        incoherent.clear()
        other.clear()
        cursor[0] = 0
        stop.clear()
        writer = threading.Thread(target=tamperer, daemon=True)
        writer.start()
        pool = [threading.Thread(target=worker) for _ in range(threads)]
        for thread in pool:
            thread.start()
        for thread in pool:
            thread.join()
        stop.set()
        writer.join(10)

    result = _measure(
        run,
        name="state_commit_tamper",
        operations=threads * per_thread,
        threads=threads,
        per_thread=per_thread,
        errors=errors,
    )

    total = sum(allowed) + sum(incoherent) + len(other)
    result["allowed_last_run"] = sum(allowed)
    result["coherence_denials_last_run"] = sum(incoherent)
    result["other_denials_last_run"] = len(other)
    result["other_denial_reasons"] = sorted(set(other))
    result["decisions_last_run"] = total
    result["denied_fraction"] = (
        round((total - sum(allowed)) / total, 4) if total else None
    )
    if total != threads * per_thread:
        result["error"] = (
            f"{total} decisions from {threads * per_thread} requests: "
            "a request neither allowed nor denied"
        )
    if errors:
        result["error"] = (
            f"authorize raised under silent mutation: {errors[0]}"
        )
    return result


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
    # v2.5: the continuous-authorization path the boundary fixes made
    # more expensive.
    "context_snapshot": benchmark_context_snapshot,
    "continuous_authorize": benchmark_continuous_authorize,
    "continuous_revalidate": benchmark_continuous_revalidate,
    # v2.6: the authority epoch, and what it costs a request that races a
    # widening write rather than merely a hostile input.
    "epoch_primitives": benchmark_epoch_primitives,
    "authorize_epoch": benchmark_authorize_epoch,
    "authorize_under_widening": benchmark_authorize_under_widening,
    "epoch_contention": benchmark_epoch_contention,
    # v2.7: the execution lease -- authorize, then keep the authority
    # attached to the act.
    "execution_authorize_only": benchmark_execution_authorize_only,
    "execution_issue": benchmark_execution_issue,
    "execution_validate": benchmark_execution_validate,
    "execution_reserve": benchmark_execution_reserve,
    "execution_denied": benchmark_execution_denied,
    # v2.8: the side-effect commit protocol.
    "effect_authorize": benchmark_effect_authorize,
    "effect_lease": benchmark_effect_lease,
    "effect_intent": benchmark_effect_intent,
    "effect_attempt": benchmark_effect_attempt,
    "effect_receipt": benchmark_effect_receipt,
    "effect_commit": benchmark_effect_commit,
    "effect_reconcile": benchmark_effect_reconcile,
    # v2.9: the verification stage between OBSERVED and COMPLETED.
    "effect_verify": benchmark_effect_verify,
    "effect_unverified_commit": benchmark_effect_unverified_commit,
    # v3.0: the security state-commitment layer.
    "state_commit_authorize": benchmark_state_commit_authorize,
    "state_commit_transition": benchmark_state_commit_transition,
    "state_commit_tamper": benchmark_state_commit_tamper,
}

#: Named groups, so ``python -m firewall.benchmarks aegis`` runs the v2.4
#: set without anyone having to remember twelve names, and
#: ``python -m firewall.benchmarks boundary`` runs the v2.5 set. Expanded in
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
    "boundary": (
        "context_snapshot",
        "continuous_authorize",
        "continuous_revalidate",
    ),
    "epoch": (
        "epoch_primitives",
        "authorize_epoch",
        "authorize_under_widening",
        "epoch_contention",
    ),
    "execution": (
        "execution_authorize_only",
        "execution_issue",
        "execution_validate",
        "execution_reserve",
        "execution_denied",
    ),
    "side_effect": (
        "effect_authorize",
        "effect_lease",
        "effect_intent",
        "effect_attempt",
        "effect_receipt",
        "effect_commit",
        "effect_reconcile",
    ),
    "verification": (
        "effect_verify",
        "effect_unverified_commit",
    ),
    "state": (
        "state_commit_authorize",
        "state_commit_transition",
        "state_commit_tamper",
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

    Groups include ``v21``, ``aegis``, ``boundary``, ``epoch``,
    ``execution``, ``side_effect``, ``verification`` and ``state``;
    with no arguments every benchmark runs. Exit status is 1 if any
    benchmark errored, so this is usable as a smoke check as well as
    a measurement.
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
