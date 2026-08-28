"""Console service layer.

Composes the read-only projections in :mod:`firewall.ui.introspect` with
the demo scenarios in :mod:`firewall.ui.demo` into the payloads the
browser consumes.

This layer contains no authorization logic. When it needs a decision it
calls the established ``FirewallSDK`` pipeline and reports the result
verbatim.

Two modes:

``demo``
    The console owns self-contained demo workspaces. Scenarios may be
    evaluated, because the SDK being mutated was created by the console
    for that purpose and is discarded afterwards.

``attached``
    A caller supplied a live ``FirewallSDK``. The console then reads
    posture, inventory, and lifecycle from it but **refuses to evaluate
    scenarios**, because evaluation has real security side effects
    (lifecycle records, risk escalation, refusal memoization, budget and
    replay consumption) and a local inspection console has no business
    causing them on a live system.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.ui import introspect
from firewall.ui.control import ControlPlane
from firewall.ui.demo import (
    SCENARIOS_BY_ID,
    DemoRequest,
    _workspace,
    scenario_catalog,
)


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version(
            "agent-firewall-security"
        )
    except Exception:
        return "unknown"


class ConsoleError(Exception):
    """Raised for a bad console request."""


class Console:
    """Read-oriented view over Agent Firewall for the developer console."""

    def __init__(
        self,
        sdk: Optional[FirewallSDK] = None,
        *,
        history_limit: int = 50,
    ):
        if sdk is not None and not isinstance(
            sdk,
            FirewallSDK,
        ):
            raise TypeError(
                "sdk must be a FirewallSDK"
            )

        self._attached = sdk
        self._reference: Optional[
            FirewallSDK
        ] = None
        self._workbench: Optional[
            FirewallSDK
        ] = None
        self._control: Optional[
            ControlPlane
        ] = None
        self._history: deque[
            dict[str, Any]
        ] = deque(
            maxlen=history_limit
        )

        # v1.8: the demo flight recorder is built lazily so a read-only
        # attached console that never opens the recorder panel pays
        # nothing for it.
        self._demo_recorder = None
        self._demo_recorder_sdk = None
        self._containment = None

    # ------------------------------------------------------------------
    # Mode
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return (
            "attached"
            if self._attached is not None
            else "demo"
        )

    @property
    def can_evaluate(self) -> bool:
        """Scenario evaluation is demo-mode only."""

        return self._attached is None

    def _pipeline_source(self) -> FirewallSDK:
        """An SDK to read the canonical gate order from.

        The gate tuple is a property of the implementation, identical
        across instances, so a throwaway instance is a faithful source
        when no live SDK is attached.
        """

        if self._attached is not None:
            return self._attached

        if self._reference is None:
            self._reference = FirewallSDK()

        return self._reference

    # ------------------------------------------------------------------
    # Control plane
    # ------------------------------------------------------------------

    def workbench(self) -> FirewallSDK:
        """The SDK the control plane writes to.

        Attached mode writes to the live SDK -- that is the point of
        attaching one. Demo mode gets a durable in-memory workspace of
        its own, so rules authored in the browser persist for the life
        of the process without touching anything real.
        """

        if self._attached is not None:
            return self._attached

        if self._workbench is None:
            self._workbench = _workspace(
                recorder=self._demo_recorder
            )

        return self._workbench

    def control(self) -> ControlPlane:
        """Lazily create the audited write surface.

        Nothing calls this unless the server was started with control
        explicitly enabled, so a plain inspection console never even
        constructs one.
        """

        if self._control is None:
            self._control = ControlPlane(
                self.workbench()
            )

        return self._control

    # ------------------------------------------------------------------
    # v1.8 flight recorder
    # ------------------------------------------------------------------

    def _recorder(self):
        """The recorder this console projects.

        Demo mode: a dedicated recorder fed by a scripted session plus
        live control-plane activity. Attached mode: the SDK's own
        recorder, if it has one.
        """

        if self._attached is not None:
            return getattr(
                self._attached,
                "flight_recorder",
                None,
            )

        if self._demo_recorder is None:
            from firewall.ui.v18 import (
                build_demo_session,
            )

            recorder, sdk = build_demo_session()

            self._demo_recorder = recorder
            self._demo_recorder_sdk = sdk

        return self._demo_recorder

    def recorder_view(self) -> dict[str, Any]:
        """The read-only recorder projection for the browser."""

        recorder = self._recorder()

        if recorder is None:
            return {
                "available": False,
                "reason": (
                    "no flight recorder attached to this "
                    "FirewallSDK"
                ),
            }

        from firewall.ui.v18 import (
            containment_projection,
            recorder_projection,
        )

        projection = recorder_projection(recorder)
        projection["available"] = True
        projection["containment"] = (
            containment_projection(
                self._containment_controller()
            )
        )
        return projection

    def replay(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Counterfactual replay over the recorded session."""

        recorder = self._recorder()

        if recorder is None:
            raise ConsoleError(
                "no flight recorder available to replay"
            )

        from firewall.ui.v18 import replay_projection

        return replay_projection(
            recorder,
            payload,
        )

    def _containment_controller(self):
        """The containment controller for the console's SDK."""

        if self._containment is None:
            from firewall.containment import (
                ContainmentController,
            )

            recorder = self._recorder()

            self._containment = ContainmentController(
                self.workbench(),
                recorder=recorder,
                authorizer=lambda: True,
            )

        return self._containment

    def apply_containment(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply one containment action (control-plane write)."""

        from firewall.containment import (
            ContainmentAction,
            ContainmentError,
        )
        from firewall.ui.v18 import (
            containment_projection,
        )

        raw_action = payload.get("action")

        if not isinstance(raw_action, str):
            raise ContainmentError(
                "action must be a string"
            )

        try:
            action = ContainmentAction(raw_action)
        except ValueError:
            raise ContainmentError(
                f"unknown containment action: {raw_action}"
            ) from None

        agent = payload.get("agent")
        reason = payload.get("reason")
        actor = payload.get("actor", "console")

        if not isinstance(agent, str) or not agent.strip():
            raise ContainmentError(
                "agent must be a non-empty string"
            )

        if not isinstance(reason, str) or not reason.strip():
            raise ContainmentError(
                "reason is required for every containment action"
            )

        controller = self._containment_controller()

        event = controller.apply(
            action,
            agent,
            actor=actor,
            reason=reason,
        )

        return {
            "event": event.to_dict(),
            "containment": (
                containment_projection(controller)
            ),
        }

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def system(self) -> dict[str, Any]:
        sdk = self._pipeline_source()

        return {
            "version": _package_version(),
            "mode": self.mode,
            "can_evaluate": self.can_evaluate,
            "pipeline": introspect.pipeline_phases(
                sdk
            ),
            "max_delegation_depth": (
                sdk.max_delegation_depth
            ),
            "decision_source": (
                "FirewallSDK.authorize_north_star()"
            ),
            "recorder_available": (
                self._recorder() is not None
            ),
        }

    def scenarios(self) -> dict[str, Any]:
        return {
            "scenarios": scenario_catalog(),
            "can_evaluate": self.can_evaluate,
        }

    # ------------------------------------------------------------------
    # Attached-system reads
    # ------------------------------------------------------------------

    def posture(self) -> dict[str, Any]:
        sdk = self._pipeline_source()

        return {
            "mode": self.mode,
            "posture": introspect.posture_view(
                sdk
            ),
            "lifecycle_totals": (
                introspect.lifecycle_totals(sdk)
            ),
        }

    def lifecycle(
        self,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        sdk = self._pipeline_source()

        return {
            "mode": self.mode,
            "events": introspect.lifecycle_view(
                sdk,
                limit=limit,
            ),
        }

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def history(self) -> dict[str, Any]:
        return {
            "history": list(self._history)
        }

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        scenario_id: str,
    ) -> dict[str, Any]:
        """Run one demo scenario through the real authorization pipeline."""

        if not self.can_evaluate:
            raise ConsoleError(
                "scenario evaluation is disabled while attached "
                "to a live FirewallSDK"
            )

        scenario = SCENARIOS_BY_ID.get(
            scenario_id
        )

        if scenario is None:
            raise ConsoleError(
                f"unknown scenario: {scenario_id}"
            )

        prepared = scenario.builder()

        return self._evaluate_prepared(
            scenario_id=scenario_id,
            scenario_title=scenario.title,
            expects=scenario.expects,
            prepared=prepared,
        )

    def _evaluate_prepared(
        self,
        *,
        scenario_id: str,
        scenario_title: str,
        expects: str,
        prepared: DemoRequest,
    ) -> dict[str, Any]:
        sdk = prepared.sdk

        # Replay any prerequisite requests through the same real
        # pipeline so state-dependent scenarios are genuine.
        warmup: list[dict[str, Any]] = []

        for (
            capability,
            action,
            request,
        ) in prepared.warmup:
            prior = sdk.authorize_north_star(
                capability,
                action,
                request,
            )
            warmup.append(
                {
                    "action": action,
                    "allowed": bool(
                        prior.allowed
                    ),
                    "reason": prior.reason,
                }
            )

        # The observed decision. This is the real pipeline; the console
        # only renders what comes back.
        decision = sdk.authorize_north_star(
            prepared.capability,
            prepared.action,
            prepared.request,
        )

        decision_payload = (
            introspect.decision_view(decision)
        )

        phases = introspect.phase_trace(
            sdk,
            allowed=decision.allowed,
            reason=decision.reason,
        )

        attributed = introspect.attribute_reason(
            decision.reason
        )

        authority: Optional[dict[str, Any]] = None

        if isinstance(
            prepared.capability,
            Capability,
        ):
            authority = introspect.authority_view(
                sdk,
                prepared.capability,
            )

        inventory = [
            introspect.capability_view(sdk, item)
            for item in prepared.inventory
        ]

        actual = decision.reason or ""

        record = {
            "scenario": scenario_id,
            "title": scenario_title,
            "request": {
                "action": prepared.action,
                "payload": dict(
                    prepared.request
                ),
                "capability_presented": isinstance(
                    prepared.capability,
                    Capability,
                ),
            },
            "decision": decision_payload,
            "attributed_phase": attributed,
            "phases": phases,
            "authority": authority,
            "inventory": inventory,
            "warmup": warmup,
            "notes": list(prepared.notes),
            "expectation": {
                "expects": expects,
                "actual": actual,
                "matches": (
                    actual == expects
                    or actual.startswith(
                        expects
                    )
                ),
            },
            "lifecycle": introspect.lifecycle_view(
                sdk,
                limit=40,
            ),
            "posture": introspect.posture_view(
                sdk,
                agents=prepared.agents,
            ),
        }

        self._history.appendleft(
            {
                "scenario": scenario_id,
                "title": scenario_title,
                "allowed": decision_payload[
                    "allowed"
                ],
                "reason": decision_payload[
                    "reason"
                ],
                "agent": decision_payload["agent"],
                "action": decision_payload[
                    "action"
                ],
                "attributed_phase": attributed,
            }
        )

        # A demo workspace is disposable. Release its resources so a
        # long-running console does not accumulate them.
        if sdk is not self._attached:
            try:
                sdk.close()
            except Exception:
                pass

        return record
