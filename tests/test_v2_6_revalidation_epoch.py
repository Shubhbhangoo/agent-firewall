"""v2.6: the revalidation fast path cannot serve an allow across a widening.

``ContinuousAuthorizationEngine.revalidate`` has a fast path: it captures
a snapshot of security state, and if the digest matches the one behind the
cached verdict it reports that verdict without calling
``FirewallSDK.authorize()`` again. That is the whole point of the surface
-- re-running eleven gates per heartbeat would make continuous
authorization unaffordable.

It also carries the same shape of defect the boundary had, for a related
but distinct reason. ``_capture_snapshot`` runs *outside* the engine lock
and reads its nineteen-odd fields one at a time, so a write landing
mid-capture yields a digest over mixed reads. v2.5 closed the case where
the digest *differs*; it could not close the case where a digest over
mixed reads happens to **equal** the original -- describing a state that
never existed, and serving the cached allow.

The fix is not to enumerate more fields. Enumerating gate inputs does not
terminate, and worse, ``aegis_restrictions`` can legitimately return to a
previous value: suspend, lift, and the digest is what it was before, with
a window in between. A monotonic counter cannot do that, so including the
authority epoch in the snapshot makes any widening -- including one that
nets out to nothing -- visible to the comparison.

The cost is stated rather than hidden: one widening anywhere invalidates
every cached verdict, because the epoch is global. These tests pin both
the property and its cost.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

import pytest

from firewall.aegis import AegisController
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.sdk import FirewallSDK

ACTION = "payments.transfer"
REQUEST = {"amount": 10}


def build() -> tuple[FirewallSDK, AegisController]:
    """An SDK with continuous authorization wired and Aegis attached.

    Periodic revalidation is off: a background sweep would repopulate the
    cache and the fast path under test would stop being the path taken.
    """

    controller = AegisController()
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    sdk.generate_key("v26-reval")

    return sdk, controller


def issue(sdk: FirewallSDK, controller: AegisController) -> Any:
    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.*",
        constraints={"amount_max": 100},
    )
    controller.register(
        sdk.fingerprint(capability),
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    return capability


def cached(sdk: FirewallSDK, capability: Any) -> None:
    """Take the decision the fast path will later answer from."""

    first = sdk.authorize_continuous(capability, ACTION, REQUEST)

    assert first.allowed, first.reason


def snapshot(sdk: FirewallSDK, capability: Any):
    return sdk.continuous_auth_engine._capture_snapshot(
        capability,
        ACTION,
        REQUEST,
    )


class TestTheEpochEntersTheDigest:
    """Structural: the counter is in the snapshot and in its hash.

    A field the snapshot carries but the hash ignores would leave the fast
    path exactly as it was. ``_HASH_EXCLUDED_FIELDS`` is the mechanism
    that could do that silently, so it is checked by name.
    """

    def test_the_snapshot_carries_the_epoch(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)

        state = snapshot(sdk, capability)
        sdk.close()

        assert state.authority_epoch == "0:0", state.authority_epoch

    def test_the_epoch_is_not_excluded_from_the_hash(self) -> None:
        from firewall.continuous_auth.engine import (
            _HASH_EXCLUDED_FIELDS,
        )

        assert "authority_epoch" not in _HASH_EXCLUDED_FIELDS

    def test_a_widening_changes_the_state_hash(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)

        before = snapshot(sdk, capability).state_hash()
        sdk.refusal_state.clear_all()
        after = snapshot(sdk, capability).state_hash()

        sdk.close()

        assert before != after


class TestTheFastPathCannotServeAnAllowAcrossAWidening:
    """The security property, on the surface the boundary tests do not reach.

    Each test primes the cache with an allow, performs a widening, and then
    revalidates. The requirement is that the fast path is *not* taken: the
    result must report a state change, and the drift must name the epoch.

    Naming the epoch in the drift is what distinguishes this from the v2.5
    behaviour. A write that also moved some enumerated field would have
    been caught before; the point here is that the epoch catches it whether
    or not any enumerated field moved.
    """

    @pytest.mark.parametrize(
        "label,widen",
        [
            (
                "refusals_cleared",
                lambda sdk, controller, fp: sdk.refusal_state.clear_all(),
            ),
            (
                "issuer_trusted",
                lambda sdk, controller, fp: sdk.trust_issuer("late"),
            ),
            (
                "risk_reset",
                lambda sdk, controller, fp: controller.store.lift(
                    fp,
                    key="no-such-incident",
                ),
            ),
        ],
    )
    def test_a_widening_defeats_the_fast_path(
        self,
        label,
        widen,
    ) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        widen(sdk, controller, sdk.fingerprint(capability))

        result = sdk.revalidate(capability, ACTION, REQUEST)
        sdk.close()

        assert result.state_changed is True
        assert result.reason != "no_material_state_change"

        drift = result.details["change_reasons"]

        assert any(
            item.startswith("authority_epoch:") for item in drift
        ), drift

    def test_a_net_zero_restriction_edit_is_still_a_change(self) -> None:
        """The case an enumerated digest provably cannot catch.

        Suspend then lift: ``aegis_restrictions`` ends where it started, so
        a digest over restrictions alone matches the cached one and the
        fast path serves the cached allow. But there was a window, and the
        history is not net-zero even though the state is. The epoch is
        monotonic and cannot return to a previous value, so it sees it.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        fingerprint = sdk.fingerprint(capability)
        cached(sdk, capability)

        restrictions_before = snapshot(sdk, capability).aegis_restrictions

        controller.suspend(
            fingerprint,
            key="incident-1",
            reason="net-zero probe",
        )
        controller.store.lift(fingerprint, key="incident-1")

        restrictions_after = snapshot(sdk, capability).aegis_restrictions

        result = sdk.revalidate(capability, ACTION, REQUEST)
        direct = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert restrictions_before == restrictions_after, (
            "the premise of this test is that the enumerated digest is "
            "unchanged; if it moved, the epoch is not what caught this"
        )
        assert result.state_changed is True
        assert result.revalidated_allowed is True
        assert direct.allowed is True

        drift = result.details["change_reasons"]

        assert any(
            item.startswith("authority_epoch:") for item in drift
        ), drift
        assert not any(
            item.startswith("aegis_restrictions:") for item in drift
        ), drift


class TestTheControlAndTheCost:
    """What still works, and what the mechanism charges for it.

    Both halves have to be stated. A change that made every revalidation
    report a state change would pass every test above and destroy the fast
    path; a change that kept the fast path but did not invalidate on a
    widening would be the original bug. The cost is real and is asserted
    here rather than left for someone to discover in production.
    """

    def test_without_a_widening_the_fast_path_is_still_taken(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        result = sdk.revalidate(capability, ACTION, REQUEST)
        sdk.close()

        assert result.state_changed is False
        assert result.revalidated_allowed is True
        assert result.reason == "no_material_state_change"

    def test_a_narrowing_write_is_still_noticed(self) -> None:
        """v2.5's property must survive v2.6's addition."""

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        controller.suspend(
            sdk.fingerprint(capability),
            key="incident-1",
            reason="probe",
        )

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)
        sdk.close()

        assert direct.allowed is False
        assert result.revalidated_allowed is False
        assert result.state_changed is True

    def test_one_widening_invalidates_every_cached_verdict(self) -> None:
        """The stated cost of a single global counter.

        The epoch is not per-capability, so a widening aimed at one agent
        invalidates the cache for an unrelated one. This is the price of a
        counter whose completeness can be argued from a case analysis
        rather than from a claim about which fields matter. It costs
        recomputation, never permission -- the recomputation runs the
        canonical boundary.
        """

        sdk, controller = build()
        first = issue(sdk, controller)
        second = sdk.issue(
            agent="other-agent",
            capability="payments.*",
            constraints={"amount_max": 100},
        )
        controller.register(
            sdk.fingerprint(second),
            agent_id=second.agent_id,
            capability=second.capability,
        )

        cached(sdk, first)
        cached(sdk, second)

        sdk.refusal_state.clear(
            agent="probe-agent",
            capability_fingerprint=sdk.fingerprint(first),
            action=ACTION,
            request=REQUEST,
        )

        unrelated = sdk.revalidate(second, ACTION, REQUEST)
        sdk.close()

        assert unrelated.state_changed is True
        assert unrelated.revalidated_allowed is True, (
            "the cost is recomputation, not a denial"
        )

    def test_an_unreadable_epoch_degrades_rather_than_passing(self) -> None:
        """A probe that raises must subtract, not be ignored.

        ``unknown is not trusted``: if the epoch cannot be sampled, the
        snapshot records the failure in ``degraded_dependencies`` so the
        engine treats the state as unreadable. Silently substituting a
        plausible value would convert an unverifiable reading into
        permission.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)

        class Exploding:
            def sample(self):
                raise RuntimeError("probe failure")

        sdk.authority_epoch = Exploding()

        state = snapshot(sdk, capability)
        sdk.close()

        assert "authority_epoch" in state.degraded_dependencies

    def test_concurrent_revalidations_all_terminate(self) -> None:
        """Six revalidations and a widening, sharing one engine.

        ``_capture_snapshot`` runs outside the engine lock by design, so
        this is the surface where concurrent captures overlap. No verdict
        assertion -- the writes make several outcomes legitimate -- only
        that every call returns.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        errors: list[BaseException] = []
        lock = threading.Lock()

        def revalidator():
            try:
                for _ in range(5):
                    sdk.revalidate(capability, ACTION, REQUEST)
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)

        def writer():
            try:
                for _ in range(5):
                    sdk.refusal_state.clear_all()
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)

        threads = [
            threading.Thread(target=revalidator, daemon=True)
            for _ in range(6)
        ] + [threading.Thread(target=writer, daemon=True)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(30)

        alive = [thread for thread in threads if thread.is_alive()]
        sdk.close()

        assert not alive, "a concurrent revalidation never returned"
        assert not errors, errors
