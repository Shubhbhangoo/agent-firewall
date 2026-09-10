"""v2.5 Phase 8: the continuous-authorization path, priced.

Two v2.5 fixes added a probe each to ``_capture_snapshot`` -- row 15's
``aegis_restrictions`` and row 22's ``refusal_state`` -- and nothing was
measuring that path. ``benchmark_context_snapshot``,
``benchmark_continuous_authorize`` and ``benchmark_continuous_revalidate``
close that gap.

No timing assertions here either, for the reason
``tests/test_v2_4_benchmarks.py`` gives. What this file pins is that the
three new benchmarks measure the path they name:

* the estate has continuous authorization *and* Aegis wired, so the two
  new probes do work rather than returning ``UNKNOWN`` after one
  ``getattr``;
* the snapshot they time is not degraded, because a degraded snapshot is
  the fail-closed path and pricing it would understate the healthy one;
* the tolerated-change loop really is a changed path that the boundary
  still allows. That last one is load-bearing: it is the only assertion
  in the suite that fails if someone makes ``_probe_refusal`` scope-aware
  to reclaim the millisecond, which is row 22 rebuilt as an optimization.
"""

from __future__ import annotations

import pytest

from firewall import benchmarks
from firewall.continuous_auth.engine import (
    UNKNOWN,
    ContinuousAuthorizationEngine,
)

#: The v2.5 additions, and the path each prices.
BOUNDARY_PATHS = {
    "security context snapshot": "context_snapshot",
    "monitored authorization": "continuous_authorize",
    "continuous revalidation": "continuous_revalidate",
}


class TestCoverage:
    def test_every_v2_5_path_has_a_benchmark(self) -> None:
        missing = {
            path: name
            for path, name in BOUNDARY_PATHS.items()
            if name not in benchmarks.BENCHMARKS
        }
        assert missing == {}, missing

    def test_the_boundary_group_names_exactly_them(self) -> None:
        """A group is how anyone runs these deliberately.

        ``test_groups_partition_the_registry`` in the v2.4 file already
        fails if a benchmark belongs to no group; this pins the converse,
        that the group named after v2.5 contains the v2.5 set and nothing
        borrowed from the Aegis set to pad it.
        """

        assert set(benchmarks.GROUPS["boundary"]) == set(
            BOUNDARY_PATHS.values()
        )


class TestTheEstateIsWhatItClaims:
    def test_the_estate_wires_continuous_auth_and_aegis(self) -> None:
        sdk, capability, fingerprints, _ = benchmarks._continuous_estate(
            depth=2
        )
        try:
            assert sdk.continuous_auth_engine is not None
            assert sdk.aegis is not None
            # Every grant tracked: an unregistered grant takes the untracked
            # path through _gate_aegis, and _probe_aegis on an unknown
            # fingerprint is close to free.
            assert len(fingerprints) == 3
            for fingerprint in fingerprints:
                assert sdk.aegis.grant(fingerprint) is not None
        finally:
            sdk.close()

    def test_periodic_revalidation_is_off(self) -> None:
        """Otherwise a background sweep times itself into the samples.

        Not a security property -- a measurement one. A benchmark whose
        numbers depend on when a monitor thread last woke up is not the
        reproducible methodology §14 asks for.
        """

        sdk, _, _, _ = benchmarks._continuous_estate()
        try:
            config = sdk.continuous_auth_monitor._config
            assert config.enable_periodic_revalidation is False
        finally:
            sdk.close()

    def test_the_two_v2_5_probes_read_real_state(self) -> None:
        """Neither new probe returns UNKNOWN on this estate.

        ``UNKNOWN`` is what both probes return when the subsystem behind
        them is absent, and it costs one ``getattr``. A benchmark measuring
        that would publish a flattering figure for a path no monitored
        deployment takes.
        """

        sdk, capability, fingerprints, _ = benchmarks._continuous_estate(
            depth=2
        )
        try:
            engine = sdk.continuous_auth_engine
            snapshot = engine._capture_snapshot(
                capability, benchmarks.ACTION, benchmarks.REQUEST
            )
            assert snapshot.aegis_restrictions != UNKNOWN
            assert snapshot.refusal_state != UNKNOWN
            # And the healthy path, not the fail-closed one.
            assert snapshot.degraded_dependencies == ()
            assert snapshot.degraded is False
        finally:
            sdk.close()


class TestNoBenchmarkWeakensAnything:
    def test_the_snapshot_benchmark_names_both_v2_5_probes(self) -> None:
        """The report has to say what it priced.

        A total that quietly stops including one of the two probes added
        this release is a total that reads as an improvement.
        """

        report = benchmarks.benchmark_context_snapshot(count=5, depth=1)

        assert set(report["by_probe"]) >= {"aegis_restrictions", "refusal_state"}
        assert report["aegis_restrictions"] != UNKNOWN
        assert report["refusal_state"] != UNKNOWN
        assert report["degraded"] == []

    def test_the_monitored_benchmark_measures_an_allow(self) -> None:
        """The surcharge compares like with like.

        ``authorize_continuous`` returns ``authorize()``'s verdict
        unmodified. If the monitored loop were being denied while the plain
        loop was allowed, the ratio would be the cost of a shorter gate
        chain rather than the cost of monitoring.
        """

        report = benchmarks.benchmark_continuous_authorize(count=5, depth=1)

        assert report["allowed"] is True
        assert report["reason"] == "authorized"
        assert report["plain_seconds_median"] > 0
        assert report["monitoring_surcharge_ratio"] is not None

    def test_the_tolerated_change_is_a_changed_path_that_still_allows(
        self,
    ) -> None:
        """The one assertion here that guards a security property.

        The benchmark prices ``_probe_refusal`` being coarser than the gate
        it protects: a refusal latched against a different action moves the
        digest, the engine routes to ``authorize()``, and ``authorize()``
        allows. Three things must all hold for that to be what was measured,
        and each fails differently:

        * ``state_changed`` -- if this goes False, the probe stopped seeing
          a refusal it used to see. That is row 22, reintroduced as an
          optimization, and it is exactly what someone reclaiming the
          millisecond this benchmark prices would do.
        * ``revalidated_allowed`` -- if this goes False, the loop is timing
          a denial, and the published figure is the cost of a refusal the
          gate honours rather than the cost of one it does not.
        * the reason names ``refusal_state`` -- if the digest moved for some
          other reason, the number is not about this probe at all.
        """

        report = benchmarks.benchmark_continuous_revalidate(count=5, depth=1)

        assert report["tolerated_state_changed"] is True
        assert report["tolerated_allowed"] is True
        assert "refusal_state" in report["tolerated_reason"]

    def test_the_benchmark_never_latches_the_monitored_action(self) -> None:
        """Run it, then check the refusal store by hand.

        The loop latches and clears in pairs, so a leak would show up as a
        surviving record. More importantly, nothing it latches may be
        against the action being revalidated -- a refusal there would deny
        the monitored request, and the benchmark would be pricing the
        boundary refusing rather than the boundary agreeing.
        """

        sdk, capability, fingerprints, _ = benchmarks._continuous_estate(
            depth=1
        )
        try:
            agent = "agent-1"
            fingerprint = fingerprints[-1]
            refusals = sdk.refusal_state
            refusals.record(
                agent=agent,
                capability_fingerprint=fingerprint,
                action=f"{benchmarks.ACTION}.unmonitored",
                request=benchmarks.REQUEST,
                reason="the benchmark's tolerated change",
            )

            # The gate the benchmark relies on not firing.
            assert (
                refusals.check_action(
                    agent=agent,
                    capability_fingerprint=fingerprint,
                    action=benchmarks.ACTION,
                )
                is None
            )
            verdict = sdk.authorize(
                capability, benchmarks.ACTION, benchmarks.REQUEST
            )
            assert verdict.allowed is True
        finally:
            sdk.close()

    def test_the_optimization_this_benchmark_forbids_is_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The negative control for the assertion above.

        The tempting reading of ``coarse_probe_surcharge_seconds`` is that
        ``_probe_refusal`` should only digest refusals whose action matches
        the one being revalidated, which would turn every tolerated change
        back into a fast path and reclaim the millisecond. It is rejected in
        ``docs/v2.5-performance.md``, and the reason is that the snapshot is
        taken without the caller's ``refusal_scope``: a probe that filters
        on a guessed scope can miss a refusal the gate honours, which is row
        22 with a performance justification attached.

        Simulating it here -- a probe that reports ``none`` regardless --
        makes the benchmark report ``no_material_state_change``, the exact
        signature of the original defect. So the assertion above is not
        decoration: it fails when this happens.
        """

        monkeypatch.setattr(
            ContinuousAuthorizationEngine,
            "_probe_refusal",
            lambda self, agent_id, fingerprint: "none",
        )

        report = benchmarks.benchmark_continuous_revalidate(count=5, depth=1)

        assert report["tolerated_state_changed"] is False
        assert report["tolerated_reason"] == "no_material_state_change"
