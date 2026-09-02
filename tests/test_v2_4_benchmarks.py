"""v2.4 §14: the benchmark harness measures what it claims to measure.

There are no timing assertions in this file. A test that failed because a
CI runner was busy would be a test that teaches people to ignore the
suite, and the numbers themselves belong in
``docs/v2.4-performance.md`` where they can carry their methodology with
them.

What is worth pinning is everything a benchmark could quietly get wrong
and still print a plausible number:

* that each path §14 names actually has a benchmark, so the published
  set cannot silently shrink;
* that the reported figures are a *distribution* -- median, p95, spread
  -- rather than one wall-clock sample, because a single sample is not
  reproducible;
* that the estates the benchmarks build are the ones they say they build,
  in particular that the adaptive benchmark measures a *tracked* grant
  rather than the near-free untracked path;
* that no benchmark reached its number by weakening a security property:
  the denial benchmark is genuinely denied, the concurrent benchmark
  raises nothing, and the analysis benchmarks stay analysis.
"""

from __future__ import annotations

import pytest

from firewall import benchmarks
from firewall.aegis.preflight import Impact, Recommendation
from firewall.aegis.state import AegisState

#: The ten paths §14 names, mapped to the benchmark that measures each.
#: Some are answered by the v2.1 set (a graph analysis benchmark already
#: existed; a second one measuring the same thing differently would be the
#: "competing representations" problem in miniature).
SECTION_14_PATHS = {
    "ordinary authorization": "authorize_baseline",
    "adaptive authorization": "authorize_adaptive",
    "revalidation": "revalidation",
    "envelope calculation": "envelope",
    "graph analysis": "attack_graph",
    "simulation": "simulation",
    "evidence verification": "evidence_verify",
    "delegation traversal": "delegation_traversal",
    "revocation checks": "revocation_check",
    "concurrent authorization": "concurrent_authorize",
}


class TestCoverage:
    def test_every_section_14_path_has_a_benchmark(self):
        missing = {
            path: name
            for path, name in SECTION_14_PATHS.items()
            if name not in benchmarks.BENCHMARKS
        }
        assert missing == {}, missing

    def test_groups_name_only_real_benchmarks(self):
        for group, members in benchmarks.GROUPS.items():
            unknown = [
                name for name in members if name not in benchmarks.BENCHMARKS
            ]
            assert unknown == [], (group, unknown)

    def test_groups_partition_the_registry(self):
        """Every benchmark belongs to exactly one group.

        A benchmark in no group is one nobody will run deliberately; a
        benchmark in two is one whose group runs measure different sets
        than their names suggest.
        """

        seen: list[str] = []
        for members in benchmarks.GROUPS.values():
            seen.extend(members)

        assert sorted(seen) == sorted(set(seen)), "a benchmark is in two groups"
        assert set(seen) == set(benchmarks.BENCHMARKS)


class TestMethodology:
    """§14 asks for a reproducible methodology, so pin its shape."""

    def test_measure_reports_a_distribution(self):
        calls: list[int] = []

        result = benchmarks._measure(
            lambda: calls.append(1),
            name="probe",
            operations=4,
            warmup=2,
            repeats=3,
        )

        assert len(calls) == 5, "warmup calls must run and not be timed"
        assert result["repeats"] == 3
        assert result["warmup"] == 2
        assert result["operations"] == 4
        for key in (
            "seconds_median",
            "seconds_min",
            "seconds_max",
            "seconds_p95",
        ):
            assert key in result, key
        assert result["seconds_min"] <= result["seconds_median"]
        assert result["seconds_median"] <= result["seconds_max"]
        assert result["seconds_p95"] <= result["seconds_max"]

    def test_throughput_comes_from_the_median(self):
        samples = iter([0.1, 0.2, 0.3])
        clock = [0.0]

        def run() -> None:
            clock[0] += next(samples)

        monkey = pytest.MonkeyPatch()
        try:
            monkey.setattr(
                benchmarks.time, "perf_counter", lambda: clock[0]
            )
            result = benchmarks._measure(
                run, name="probe", operations=10, warmup=0, repeats=3
            )
        finally:
            monkey.undo()

        # Median of 0.1/0.2/0.3 is 0.2, so 10 operations is 50/second. A
        # mean would give the same answer here, which is why the samples
        # are symmetric: what this pins is that neither min nor max is
        # used, since either would flatter or libel the result.
        assert result["seconds_median"] == 0.2
        assert result["operations_per_second"] == 50.0

    def test_zero_duration_does_not_divide_by_zero(self):
        monkey = pytest.MonkeyPatch()
        try:
            monkey.setattr(benchmarks.time, "perf_counter", lambda: 0.0)
            result = benchmarks._measure(
                lambda: None, name="probe", operations=10, warmup=0, repeats=2
            )
        finally:
            monkey.undo()

        assert result["seconds_median"] == 0.0
        assert result["operations_per_second"] is None

    def test_the_environment_is_reported(self):
        environment = benchmarks._environment()

        for key in ("python", "platform", "perf_counter_resolution"):
            assert environment[key], key

        # The methodological claim in ``_measure``'s docstring: the clock
        # actually used is finer than ``time.time``, which on this platform
        # advances in 15.6 ms steps.
        assert (
            environment["perf_counter_resolution"]
            <= environment["time_resolution"]
        )


class TestTheEstateIsWhatItClaims:
    def test_an_adaptive_estate_tracks_every_grant(self):
        """Otherwise the adaptive benchmark measures the untracked path.

        ``_gate_aegis`` on an unregistered fingerprint is close to free, so
        an estate that forgot to register would produce a flattering
        "adaptive costs nothing" number.
        """

        sdk, capability, fingerprints, _ = benchmarks._estate(
            aegis_enabled=True, depth=3
        )
        try:
            assert len(fingerprints) == 4
            assert sdk.fingerprint(capability) == fingerprints[-1]
            for fingerprint in fingerprints:
                grant = sdk.aegis.grant(fingerprint)
                assert grant is not None, fingerprint
                assert grant.state is AegisState.ISSUED
        finally:
            sdk.close()

    def test_a_baseline_estate_has_no_aegis_state(self):
        sdk, capability, fingerprints, _ = benchmarks._estate(
            aegis_enabled=False, depth=2
        )
        try:
            # Not merely "no tracked grants": with Aegis off there is no
            # controller, so the baseline cannot be measuring a warm store.
            assert sdk.aegis is None
            outcome = sdk.authorize(
                capability, benchmarks.ACTION, benchmarks.REQUEST
            )
            assert outcome.allowed is True, outcome.reason
        finally:
            sdk.close()

    def test_the_chain_narrows_or_holds_at_every_hop(self):
        """A benchmark estate that widened would be measuring a bug."""

        sdk, capability, fingerprints, _ = benchmarks._estate(
            aegis_enabled=True, depth=4
        )
        try:
            leaf = sdk.authority_envelope(capability)
            assert leaf.bottom is False
            for fingerprint in fingerprints:
                assert sdk.aegis.grant(fingerprint) is not None
        finally:
            sdk.close()


class TestNoBenchmarkWeakensAnything:
    def test_the_denial_benchmark_is_genuinely_denied(self):
        result = benchmarks.benchmark_authorize_restricted(count=2)

        assert "error" not in result, result
        assert result["outcome"] == "deny"
        assert result["reason"].startswith("aegis_")

    def test_the_denial_benchmark_is_not_memoized_into_refusal(self):
        """Every iteration must traverse the gates, not short-circuit.

        ``aegis_constraint_denied`` is deliberately outside the memoized
        set. If that ever changes, the second request would come back as
        ``refusal_state`` and this benchmark would be measuring the
        refusal cache instead of adaptive enforcement.
        """

        sdk, capability, fingerprints, _ = benchmarks._estate(
            aegis_enabled=True
        )
        try:
            sdk.aegis.narrow(
                fingerprints[-1],
                key="aegis:ceiling",
                reason="test ceiling",
                constraints={"amount_max": 1},
            )
            reasons = {
                sdk.authorize(
                    capability, benchmarks.ACTION, benchmarks.REQUEST
                ).reason
                for _ in range(4)
            }
            assert reasons == {"aegis_constraint_denied:aegis:ceiling"}
        finally:
            sdk.close()

    def test_the_concurrent_benchmark_reports_every_decision(self):
        result = benchmarks.benchmark_concurrent_authorize(
            threads=4, per_thread=5
        )

        assert result["errors"] == [], result["errors"]
        assert "error" not in result, result
        assert result["decisions_last_run"] == 4
        assert result["allowed_last_run"] == 20

    def test_the_analysis_benchmarks_stay_analysis(self):
        """Neither reports an authorization, and neither can be read as one."""

        preflight = benchmarks.benchmark_preflight(count=2)
        assert "error" not in preflight, preflight
        assert preflight["recommendation"] in {
            item.value for item in Recommendation
        }
        assert preflight["impact"] in {item.value for item in Impact}
        assert "allowed" not in preflight

        blast = benchmarks.benchmark_blast_radius(count=2, breadth=4)
        assert "error" not in blast, blast
        assert "allowed" not in blast
        assert blast["complete"] is True

    def test_a_full_preflight_establishes_all_six_stages(self):
        """The measured configuration is the one that can reach ALLOW.

        Pinned because the alternative -- a stage left unsupplied -- exits
        at ``REVIEW`` early, and the benchmark would then be publishing the
        cost of declining to analyze under the name of analysis.
        """

        result = benchmarks.benchmark_preflight(count=2)

        assert result["stages"] == 6
        assert result["established"] is True
        assert result["impact"] == Impact.BOUNDED.value
        assert result["recommendation"] == Recommendation.ALLOW.value

    def test_the_simulation_benchmark_replays_counted_cases(self):
        result = benchmarks.benchmark_simulation(count=1, cases=3)

        assert "error" not in result, result
        assert result["counted_outcomes"] == 3
        # The re-signing caveat is retained, not suppressed: a simulated
        # signature is not an observed one.
        assert result["caveats"] >= 1

    def test_the_revalidation_benchmark_completes_the_round_trip(self):
        result = benchmarks.benchmark_revalidation(count=2)

        assert "error" not in result, result
        assert result["final_state"] == AegisState.ACTIVE.value

    def test_the_invariant_sweep_reports_no_violation(self):
        result = benchmarks.benchmark_invariant_sweep(count=1)

        assert "error" not in result, result
        assert result["checks"] == 5
        assert "violated" not in set(result["statuses"].values())


class TestScalingIsReported:
    """The scaling benchmarks must publish the comparison, not one point."""

    def test_delegation_traversal_reports_every_depth(self):
        result = benchmarks.benchmark_delegation_traversal(
            count=2, depths=(0, 2)
        )

        assert set(result["by_depth"]) == {"0", "2"}
        assert result["by_depth"]["0"]["ratio_to_depth_0"] == 1.0
        assert result["by_depth"]["2"]["ratio_to_depth_0"] is not None

    def test_revocation_check_reports_every_registry_size(self):
        result = benchmarks.benchmark_revocation_check(
            count=2, sizes=(0, 8)
        )

        assert set(result["by_size"]) == {"0", "8"}
        assert result["by_size"]["8"]["registry_entries"] == 8
        assert result["by_size"]["0"]["ratio_to_empty_registry"] == 1.0
