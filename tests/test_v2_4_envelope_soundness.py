"""v2.4: ENVELOPE_SOUNDNESS must not accuse a correct envelope.

Found by running the v2.3 suite, not by reading it: two consecutive runs
of the same three files failed in two *different* tests, both with the
same finding --

    [violated] ENVELOPE_SOUNDNESS: the boundary allowed a request the
    envelope states is outside the grant
        - positive control: the envelope excludes this request
          (not_yet_valid) but the boundary allowed it

-- and the accusation was false. ``check_envelope_soundness`` read the
clock *before* issuing its probe capabilities and then evaluated every
envelope at that reading. ``issue`` stamps ``issued_at`` from the clock, so
whenever the clock ticked while the five probe capabilities were being
signed, ``now`` fell before the baseline's own validity window: the
envelope correctly reported ``not_yet_valid`` for a reading at which the
capability genuinely was not yet valid, the boundary correctly allowed the
request at its own later reading, and the invariant read the disagreement
as the envelope overstating a bound.

``time.time()`` has 15.6 ms of granularity on Windows, which five
signatures cross often enough to fail a loaded CI run and rarely enough to
look like noise. That is the worst failure mode a security gate can have:
a green run proves nothing new, and a red run trains its operators to
re-run it. v2.3 removed a gate that always failed; a gate that fails at
random is the same defect wearing a different face.

The fix is one line of ordering -- read the clock after the grid exists --
and the tests here pin both halves: the reading may not precede the
capabilities it judges, and the invariant must survive a clock that ticks
mid-construction, which is the condition the real failure needed.
"""

from __future__ import annotations

import time

import pytest

from firewall.invariants import runtime
from firewall.invariants.model import InvariantStatus


class _TickingClock:
    """A clock that advances by one coarse tick on every reading.

    The real defect needed a tick to land between the ``now`` reading and
    an ``issue`` call. Sampling the real clock and hoping is not a test, so
    this makes the tick certain: every reading moves forward, which is the
    worst case the old code could meet and still a clock that never goes
    backwards.
    """

    #: The granularity of ``time.time()`` on Windows, where this was found.
    TICK = 0.015625

    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start
        self.readings = 0

    def __call__(self) -> float:
        self.readings += 1
        self.now += self.TICK

        return self.now


@pytest.fixture
def ticking(monkeypatch) -> _TickingClock:
    clock = _TickingClock()
    monkeypatch.setattr(runtime.time, "time", clock)

    return clock


class TestTheReadingFollowsTheCapabilities:
    def test_it_holds_when_the_clock_ticks_mid_construction(self, ticking):
        """The regression. Every reading advances, and the grid still holds.

        On the old ordering this is a guaranteed VIOLATED: the ``now`` used
        for every envelope predates all five capabilities, so the positive
        control is excluded as ``not_yet_valid`` while the boundary -- which
        reads the unpatched clock -- allows it.
        """

        result = runtime.check_envelope_soundness()

        assert result.status is InvariantStatus.HOLDS, result.findings
        assert ticking.readings > 1

    def test_the_positive_control_is_never_excluded(self, ticking):
        """The finding is impossible rather than merely unobserved.

        ``check_envelope_soundness`` reports a violation only when an
        excluded request was allowed, so a grid whose control is never
        excluded cannot produce this finding at all. Checked directly
        against the grid rather than through the report, because a HOLDS
        could also mean the control was excluded *and* denied.
        """

        from firewall.sdk import FirewallSDK

        sdk = FirewallSDK()
        try:
            sdk.generate_key("k")
            probes = runtime._soundness_probes(sdk, runtime.time.time())
            now = runtime.time.time()

            label, capability, action, request = probes[0]
            assert label == "positive control"

            envelope = sdk.authority_envelope(capability)

            assert envelope.excludes(action, request, now) is None
        finally:
            sdk.close()

    def test_no_probe_capability_starts_after_the_reading(self, ticking):
        """The general form: the reading judges nothing it predates.

        ``not_yet_valid`` was the symptom; the property is that the
        invariant never hands the envelope a clock reading the boundary
        could not have seen. One capability is deliberately in the past --
        the expired probe -- and none may be in the future.
        """

        from firewall.sdk import FirewallSDK

        sdk = FirewallSDK()
        try:
            sdk.generate_key("k")
            probes = runtime._soundness_probes(sdk, runtime.time.time())
            now = runtime.time.time()

            windows = [
                sdk.authority_envelope(capability).window
                for _, capability, _, _ in probes
            ]

            assert windows
            for start, _ in windows:
                assert start <= now

            # And the grid is not vacuously all-past: the expired probe is
            # the only one whose window has already closed.
            assert sum(1 for _, end in windows if end <= now) == 1
        finally:
            sdk.close()

    def test_the_real_clock_is_restored_afterwards(self):
        # The fixture patches ``runtime.time``, which is the ``time``
        # module itself -- shared with every other test in the process.
        assert runtime.time.time is time.time
