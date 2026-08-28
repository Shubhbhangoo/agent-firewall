"""v1.8 console projections: the flight recorder in the browser.

This module owns the read-only views the browser needs to make the
security recorder its visual home:

* a live recorder projection (session summary, verification status,
  timeline, trajectory, relationship graph, containment state),
* a scripted demo session so the recorder panel has genuine recorded
  material in demo mode,
* a replay-laboratory view for counterfactual policy analysis.

None of these authorize anything. The recorder is observational, the
projections derive from recorded events only, and the replay laboratory
reuses the v1.7 simulation engine with its isolated workspaces.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
)
from firewall.recorder import FlightRecorder
from firewall.replaylab import Laboratory
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.simulation import RuleSet, SimulationError
from firewall.timeline import (
    SecurityGraph,
    build_timeline,
    trajectory_from_artifact,
)
from firewall.verify import verify_artifact


def build_demo_session(
    *,
    session_id: str = "console-demo",
    agent: str = "agent-alpha",
) -> tuple[FlightRecorder, FirewallSDK]:
    """A scripted, genuinely recorded demo session.

    Runs a small agent story through the real SDK with the recorder
    attached: allow, deny, containment, recovery. The returned recorder
    owns a finalized artifact the console can render immediately.
    """

    recorder = FlightRecorder(
        session_id=session_id,
        agent=agent,
    )

    sdk = FirewallSDK(
        recorder=recorder,
        risk_context=RiskContext(),
    )
    sdk.generate_key("console-demo-key")

    capability = sdk.issue(
        agent=agent,
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    sdk.authorize(
        capability,
        "payments.send",
        {"amount": 20},
    )

    sdk.authorize(
        capability,
        "payments.send",
        {"amount": 5000},
    )

    child = sdk.delegate(
        capability,
        sdk.active_key().private_key,
        delegatee="agent-beta",
    ).child

    sdk.authorize(
        child,
        "payments.send",
        {"amount": 30},
    )

    controller = ContainmentController(
        sdk,
        recorder=recorder,
        authorizer=lambda: True,
    )
    controller.apply(
        ContainmentAction.RESTRICT_SESSION,
        agent,
        actor="console",
        reason="demo containment",
    )
    controller.apply(
        ContainmentAction.RECOVER,
        agent,
        actor="console",
        reason="demo recovery",
    )

    recorder.finalize(
        note="console demo recording"
    )

    return recorder, sdk


def recorder_projection(
    recorder: FlightRecorder,
) -> dict[str, Any]:
    """The full read-only projection of one flight recorder."""

    artifact = recorder.artifact()

    verification = verify_artifact(artifact)
    timeline = build_timeline(artifact)
    trajectory = trajectory_from_artifact(artifact)
    graph = SecurityGraph.from_artifact(artifact)

    return {
        "session": {
            "id": recorder.session_id,
            "agent": recorder.agent,
            "finalized": recorder.finalized,
            "event_count": recorder.event_count,
            "checkpoint_count": recorder.checkpoint_count,
            "recorder_fingerprint": (
                recorder.identity_fingerprint
            ),
        },
        "verification": verification.to_dict(),
        "timeline": [
            entry.to_dict() for entry in timeline
        ],
        "trajectory": trajectory.to_dict(),
        "graph": graph.to_dict(),
        "redactions": list(recorder.redactions()),
    }


def replay_projection(
    recorder: FlightRecorder,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Run the replay laboratory over the recorded session.

    The payload may name proposed rules (``max_delegation_depth``,
    ``trusted_issuers``); anything omitted inherits the recorded
    baseline, so a partial payload can never be read as "untrust
    everyone".
    """

    if not isinstance(payload, dict):
        raise ContainmentError(
            "payload must be a JSON object"
        )

    baseline = Laboratory(recorder.artifact()).baseline

    changes: dict[str, Any] = {}

    depth = payload.get("max_delegation_depth")
    issuers = payload.get("trusted_issuers")

    if depth is not None and depth != "":
        if isinstance(depth, bool) or not isinstance(
            depth, int
        ):
            raise ContainmentError(
                "max_delegation_depth must be an integer"
            )
        if depth <= 0:
            raise ContainmentError(
                "max_delegation_depth must be positive"
            )
        changes["max_delegation_depth"] = depth

    if issuers is not None:
        if not isinstance(issuers, list):
            raise ContainmentError(
                "trusted_issuers must be a list"
            )
        changes["trusted_issuers"] = [
            str(issuer) for issuer in issuers
        ]

    try:
        proposed = baseline.replace(**changes)
    except SimulationError as exc:
        raise ContainmentError(str(exc)) from exc

    laboratory = Laboratory(recorder.artifact())
    report = laboratory.replay(proposed)

    return {
        "baseline": report.baseline,
        "proposed": report.proposed,
        "summary": report.summary(),
        "rows": [
            row.to_dict() for row in report.rows
        ],
    }


def containment_projection(
    controller: ContainmentController,
) -> dict[str, Any]:
    """Read-only containment state for the browser."""

    return controller.snapshot()
