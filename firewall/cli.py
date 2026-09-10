from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.lifecycle import LifecycleEventType
from firewall.lifecycle_store import SQLiteLifecycleStore
from firewall.transport import decode_capability


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firewall",
        description="Agent Firewall command-line interface.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Kept so the v1.9 command registrars can attach new subcommands
    # without re-creating the (single) subparsers action.
    parser._firewall_subparsers = subparsers

    # ------------------------------------------------------------------
    # v1.7 configuration and inspection
    # ------------------------------------------------------------------

    init_parser = subparsers.add_parser(
        "init",
        help="Create a firewall project configuration.",
    )
    init_parser.add_argument(
        "--path",
        default="firewall.yaml",
        help="Configuration file path.",
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a firewall YAML configuration.",
    )
    validate_parser.add_argument(
        "path",
        nargs="?",
        default="firewall.yaml",
        help="Configuration file path.",
    )

    inspect_parser = subparsers.add_parser(
        "inspect-token",
        help="Decode and inspect a capability token.",
    )
    inspect_parser.add_argument(
        "token",
        help="Encoded capability token.",
    )

    explain_parser = subparsers.add_parser(
        "explain",
        help="Inspect persisted lifecycle history.",
    )
    explain_parser.add_argument(
        "path",
        help="Lifecycle SQLite database.",
    )
    explain_parser.add_argument(
        "--fingerprint",
        default=None,
    )
    explain_parser.add_argument(
        "--event-type",
        default=None,
        choices=[
            event_type.value
            for event_type in LifecycleEventType
        ],
    )
    explain_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    simulate_parser = subparsers.add_parser(
        "simulate",
        help=(
            "Replay recorded requests under a proposed rule set "
            "and report what would change."
        ),
    )
    simulate_parser.add_argument(
        "cases",
        help="Case set JSON file (see firewall.simulation).",
    )
    simulate_parser.add_argument(
        "--rules",
        default=None,
        help=(
            "Proposed rule set JSON file. Defaults to the 'before' "
            "rules with --max-depth applied."
        ),
    )
    simulate_parser.add_argument(
        "--baseline",
        default=None,
        help=(
            "Rule set the cases were recorded under. Defaults to the "
            "issuers named by the cases, with no depth ceiling."
        ),
    )
    simulate_parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Propose this delegation-depth ceiling.",
    )
    simulate_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # ------------------------------------------------------------------
    # v1.8 security flight recorder
    # ------------------------------------------------------------------

    record_parser = subparsers.add_parser(
        "record",
        help=(
            "Record a demo agent session through the real SDK and "
            "write a portable security artifact."
        ),
    )
    record_parser.add_argument(
        "--out",
        default="agent-session.afw",
        help="Artifact output path (default: agent-session.afw).",
    )
    record_parser.add_argument(
        "--agent",
        default="agent-demo",
        help="Agent name for the recorded session.",
    )

    inspect_art_parser = subparsers.add_parser(
        "inspect",
        help="Summarize a security artifact without verifying it.",
    )
    inspect_art_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    inspect_art_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Independently verify a security artifact's integrity "
            "chain and signatures."
        ),
    )
    verify_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    verify_parser.add_argument(
        "--expect-recorder",
        default=None,
        metavar="FINGERPRINT",
        help=(
            "Require the artifact to be signed by this recorder "
            "fingerprint."
        ),
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    replay_parser = subparsers.add_parser(
        "replay",
        help=(
            "Replay a recorded session in the replay laboratory, "
            "optionally under a proposed rule set (counterfactual)."
        ),
    )
    replay_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    replay_parser.add_argument(
        "--rules",
        default=None,
        help=(
            "Proposed rule set JSON file. Without it, replays under "
            "the recorded baseline rules."
        ),
    )
    replay_parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum decisions to replay (default: 200).",
    )
    replay_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    timeline_parser = subparsers.add_parser(
        "timeline",
        help="Render the security timeline of an artifact.",
    )
    timeline_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    timeline_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    trajectory_parser = subparsers.add_parser(
        "trajectory",
        help="Render the security posture trajectory of an artifact.",
    )
    trajectory_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    trajectory_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    graph_parser = subparsers.add_parser(
        "graph",
        help=(
            "Inspect the derived security relationship graph: why an "
            "agent could act, and what it could reach."
        ),
    )
    graph_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    graph_parser.add_argument(
        "--agent",
        default=None,
        help="Agent to analyze (required for --why and --reach).",
    )
    graph_parser.add_argument(
        "--why",
        default=None,
        metavar="ACTION",
        help="Show recorded reasons this agent could perform ACTION.",
    )
    graph_parser.add_argument(
        "--reach",
        action="store_true",
        help="Show what this agent could reach per recorded evidence.",
    )
    graph_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    incident_parser = subparsers.add_parser(
        "incident",
        help="Create an incident package from an artifact.",
    )
    incident_sub = incident_parser.add_subparsers(
        dest="incident_command",
        required=True,
    )
    incident_create = incident_sub.add_parser(
        "create",
        help="Bundle an artifact with verification, timeline, "
        "trajectory, graph, and replay.",
    )
    incident_create.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    incident_create.add_argument(
        "--title",
        required=True,
        help="Incident title.",
    )
    incident_create.add_argument(
        "--summary",
        default="",
        help="Short incident summary.",
    )
    incident_create.add_argument(
        "--redact",
        action="store_true",
        help=(
            "Export a redacted, re-signed copy of the artifact inside "
            "the package."
        ),
    )
    incident_create.add_argument(
        "--out",
        default="incident.json",
        help="Package output path (default: incident.json).",
    )

    redact_parser = subparsers.add_parser(
        "redact",
        help=(
            "Produce a redacted, re-signed derivation of an artifact "
            "that still verifies."
        ),
    )
    redact_parser.add_argument(
        "artifact",
        help="Path to an .afw artifact.",
    )
    redact_parser.add_argument(
        "--out",
        required=True,
        help="Redacted artifact output path.",
    )

    return parser


# ======================================================================
# Shared helpers
# ======================================================================


def _write_text(
    path: str | Path,
    content: str,
) -> None:
    target = Path(path)

    if target.parent:
        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    target.write_text(
        content,
        encoding="utf-8",
    )


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _print_json(payload: Any) -> None:
    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


# ======================================================================
# v1.7 commands
# ======================================================================


def command_init(
    path: str,
) -> int:
    target = Path(path)

    if target.exists():
        print(
            f"error: {target} already exists",
            file=sys.stderr,
        )
        return 1

    content = """# Agent Firewall configuration

trusted_issuers:
  - trusted-issuer

rules: []
"""

    _write_text(
        target,
        content,
    )

    print(
        f"created {target}"
    )

    return 0


def command_validate(
    path: str,
) -> int:
    target = Path(path)

    if not target.exists():
        print(
            f"error: configuration file not found: {target}",
            file=sys.stderr,
        )
        return 1

    try:
        import yaml

        data = yaml.safe_load(
            target.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 1

    if not isinstance(
        data,
        dict,
    ):
        print(
            "error: configuration must be a mapping",
            file=sys.stderr,
        )
        return 1

    if "rules" in data and not isinstance(
        data["rules"],
        list,
    ):
        print(
            "error: 'rules' must be a list",
            file=sys.stderr,
        )
        return 1

    print(
        f"valid: {target}"
    )

    return 0


def command_inspect_token(
    token: str,
) -> int:
    try:
        capability = decode_capability(
            token
        )

    except Exception as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 1

    _print_json(
        capability.to_dict()
    )

    return 0


def _event_to_dict(
    event,
) -> dict:
    return event.to_dict()


def _iter_explain_events(
    store: SQLiteLifecycleStore,
    *,
    fingerprint: str | None,
    event_type: str | None,
) -> Iterable:
    if fingerprint is not None:
        events = store.for_fingerprint(
            fingerprint
        )
    elif event_type is not None:
        events = store.of_type(
            LifecycleEventType(
                event_type
            )
        )
    else:
        events = store.events()

    return events


def command_explain(
    path: str,
    *,
    fingerprint: str | None,
    event_type: str | None,
    as_json: bool,
) -> int:
    target = Path(path)

    if not target.exists():
        print(
            f"error: lifecycle database not found: {target}",
            file=sys.stderr,
        )
        return 1

    store = None

    try:
        store = SQLiteLifecycleStore(
            target
        )

        events = tuple(
            _iter_explain_events(
                store,
                fingerprint=fingerprint,
                event_type=event_type,
            )
        )

        if as_json:
            _print_json(
                [
                    _event_to_dict(
                        event
                    )
                    for event in events
                ]
            )
            return 0

        if not events:
            print(
                "no lifecycle events"
            )
            return 0

        for event in events:
            print(
                f"{event.timestamp:.6f} "
                f"{event.event_type.value} "
                f"{event.fingerprint} "
                f"{event.reason}"
            )

        return 0

    except Exception as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 1

    finally:
        if store is not None:
            store.close()


def command_simulate(
    cases_path: str,
    *,
    rules: str | None = None,
    baseline: str | None = None,
    max_depth: int | None = None,
    as_json: bool = False,
) -> int:
    """Report what a proposed rule change would do to recorded traffic.

    Exit status is deliberately conservative so this is usable as a CI
    gate: ``0`` only when the change denies nothing that works today
    *and* every case was verified. "We could not tell" is not a pass.
    """

    from firewall.simulation import (
        CaseSet,
        RuleSet,
        SimulationError,
        simulate,
    )

    try:
        case_set = CaseSet.from_json(
            Path(cases_path).read_text(
                encoding="utf-8"
            )
        )
    except OSError as exc:
        print(
            f"error: cannot read {cases_path}: {exc}",
            file=sys.stderr,
        )
        return 2
    except SimulationError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 2

    try:
        if baseline is not None:
            before = RuleSet.from_json(
                Path(baseline).read_text(
                    encoding="utf-8"
                )
            )
        else:
            # Trust exactly the issuers the cases name, so the "before"
            # side reproduces the world they were recorded in rather
            # than denying everything for an unrelated reason.
            before = RuleSet(
                trusted_issuers={
                    case.issuer
                    for case in case_set
                }
            )

        if rules is not None:
            after = RuleSet.from_json(
                Path(rules).read_text(
                    encoding="utf-8"
                )
            )
        else:
            after = before.replace(
                max_delegation_depth=max_depth
            )

        report = simulate(
            case_set,
            before,
            after,
        )
    except OSError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 2
    except SimulationError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 2

    if as_json:
        print(report.to_json())
    else:
        print(report.summary())

        for line in report.description:
            print(f"  rule: {line}")

        for outcome in report.outcomes:
            if not outcome.changed:
                continue

            marker = (
                "!" if outcome.counted else "?"
            )
            print(
                f"  {marker} {outcome.change}: "
                f"{outcome.agent} {outcome.action} "
                f"({outcome.before_reason} -> "
                f"{outcome.after_reason})"
            )

        for caveat in report.caveats:
            print(f"  note: {caveat}")

    return 0 if report.safe else 1


# ======================================================================
# v1.8 commands
# ======================================================================


def command_record(
    out: str,
    agent: str,
) -> int:
    """Record a realistic demo session and write the artifact."""

    try:
        from firewall.containment import (
            ContainmentAction,
            ContainmentController,
        )
        from firewall.recorder import FlightRecorder
        from firewall.risk_context import RiskContext
        from firewall.sdk import FirewallSDK
    except Exception as exc:
        return _fail(f"cannot build recorder: {exc}")

    try:
        recorder = FlightRecorder(
            session_id="cli-demo",
            agent=agent,
        )
        sdk = FirewallSDK(
            recorder=recorder,
            risk_context=RiskContext(),
        )
        sdk.generate_key("cli-demo-key")

        cap = sdk.issue(
            agent=agent,
            capability="payments.send",
            constraints={"amount_max": 100},
        )

        sdk.authorize(
            cap,
            "payments.send",
            {"amount": 20},
        )

        sdk.authorize(
            cap,
            "payments.send",
            {"amount": 5000},
        )

        controller = ContainmentController(
            sdk,
            recorder=recorder,
            authorizer=lambda: True,
        )
        controller.apply(
            ContainmentAction.RESTRICT_SESSION,
            agent,
            actor="cli",
            reason="demo containment",
        )
        controller.apply(
            ContainmentAction.RECOVER,
            agent,
            actor="cli",
            reason="demo recovery",
        )

        recorder.finalize(
            note=f"recorded by `firewall record` for {agent}"
        )
    except Exception as exc:
        return _fail(f"recording failed: {exc}")

    try:
        from firewall.artifact import write_artifact

        write_artifact(
            recorder.artifact(),
            out,
        )
    except Exception as exc:
        return _fail(f"cannot write artifact: {exc}")

    print(f"recorded {out}")

    try:
        from firewall.artifact import session_summary

        summary = session_summary(
            recorder.artifact()
        )
        print(
            f"  session {summary['session']['id']} "
            f"({summary['event_count']} events, "
            f"{summary['checkpoint_count']} checkpoints)"
        )
        print(
            f"  recorder {summary['recorder']['fingerprint']}"
        )
    except Exception:
        pass

    return 0


def command_inspect(
    artifact_path: str,
    *,
    as_json: bool,
) -> int:
    try:
        from firewall.artifact import (
            artifact_from_path,
            session_summary,
        )
        from firewall.timeline import build_timeline
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        summary = session_summary(artifact)
        entries = build_timeline(artifact)
    except Exception as exc:
        return _fail(f"cannot inspect {artifact_path}: {exc}")

    if as_json:
        _print_json(
            {
                "summary": summary,
                "timeline": [
                    entry.to_dict() for entry in entries
                ],
            }
        )
        return 0

    print(
        f"session {summary['session'].get('id')} "
        f"agent={summary['session'].get('agent')}"
    )
    print(
        f"  events: {summary['event_count']}  "
        f"checkpoints: {summary['checkpoint_count']}  "
        f"finalized: {summary['finalized']}"
    )
    if summary["redaction_count"]:
        print(
            f"  redactions: {summary['redaction_count']}"
        )
    print(
        f"  recorder: {summary['recorder']['fingerprint']}"
    )

    for entry in entries:
        print(
            f"  {entry.seq:>4} {entry.event_type:<20} "
            f"{entry.severity:<8} {entry.title}: {entry.detail}"
        )

    return 0


def command_verify(
    artifact_path: str,
    *,
    expect_recorder: str | None,
    as_json: bool,
) -> int:
    """Verify an artifact. Exit 0 = trustworthy, 1 = incomplete,
    2 = failed/unverifiable/usage."""

    try:
        from firewall.verify import verify_artifact_path
    except Exception as exc:
        return _fail(f"cannot load verifier: {exc}")

    try:
        report = verify_artifact_path(
            artifact_path,
            expect_recorder=expect_recorder,
        )
    except Exception as exc:
        return _fail(f"cannot verify {artifact_path}: {exc}")

    if as_json:
        print(report.to_json())
    else:
        print(report.text())

    status = report.status

    if status in ("verified", "redacted"):
        return 0

    if status == "incomplete":
        return 1

    return 2


def command_replay(
    artifact_path: str,
    *,
    rules: str | None,
    limit: int,
    as_json: bool,
) -> int:
    try:
        from firewall.artifact import artifact_from_path
        from firewall.replaylab import Laboratory
        from firewall.simulation import RuleSet, SimulationError
    except Exception as exc:
        return _fail(f"cannot load replay laboratory: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        laboratory = Laboratory(artifact)

        if rules is not None:
            try:
                proposed = RuleSet.from_json(
                    Path(rules).read_text(encoding="utf-8")
                )
            except OSError as exc:
                return _fail(f"cannot read rules: {exc}")
            except SimulationError as exc:
                return _fail(f"invalid rules: {exc}")
        else:
            proposed = None

        report = laboratory.replay(
            proposed,
            limit=limit,
        )
    except Exception as exc:
        return _fail(f"replay failed: {exc}")

    if as_json:
        print(report.to_json())
    else:
        print(report.text())

    # A counterfactual that newly denies recorded activity is a finding
    # for a CI gate, but replay itself is analysis: exit 0 unless the
    # lab could not run.
    return 0


def command_timeline(
    artifact_path: str,
    *,
    as_json: bool,
) -> int:
    try:
        from firewall.artifact import artifact_from_path
        from firewall.timeline import (
            build_timeline,
            timeline_to_text,
        )
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        entries = build_timeline(artifact)
    except Exception as exc:
        return _fail(f"cannot read {artifact_path}: {exc}")

    if as_json:
        _print_json(
            [entry.to_dict() for entry in entries]
        )
        return 0

    print(timeline_to_text(entries))
    return 0


def command_trajectory(
    artifact_path: str,
    *,
    as_json: bool,
) -> int:
    try:
        from firewall.artifact import artifact_from_path
        from firewall.timeline import (
            trajectory_from_artifact,
            trajectory_to_text,
        )
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        trajectory = trajectory_from_artifact(artifact)
    except Exception as exc:
        return _fail(f"cannot read {artifact_path}: {exc}")

    if as_json:
        _print_json(trajectory.to_dict())
        return 0

    print(trajectory_to_text(trajectory))
    return 0


def command_graph(
    artifact_path: str,
    *,
    agent: str | None,
    why: str | None,
    reach: bool,
    as_json: bool,
) -> int:
    try:
        from firewall.artifact import artifact_from_path
        from firewall.timeline import SecurityGraph
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        graph = SecurityGraph.from_artifact(artifact)
    except Exception as exc:
        return _fail(f"cannot read {artifact_path}: {exc}")

    if why is not None or reach:
        if not agent:
            return _fail("--agent is required with --why/--reach")

        result: dict[str, Any] = {
            "agent": agent,
        }

        if why is not None:
            result["why_can"] = graph.why_can(agent, why)

        if reach:
            result["reachable"] = graph.reachable(agent)

        if as_json:
            _print_json(result)
            return 0

        if why is not None:
            reasons = result["why_can"]

            if not reasons:
                print(
                    f"{agent} has no recorded allow for {why}"
                )
            else:
                for reason in reasons:
                    print(
                        f"{agent} could {why} "
                        f"(decision event {reason['decision_seq']}, "
                        f"{reason['reason']})"
                    )
                    for hop in reason["path"]:
                        print(
                            f"    {hop['role']:<14} {hop['label']}"
                        )

        if reach:
            reachable = result["reachable"]
            print(f"{agent} could reach:")
            for capability in reachable["capabilities"]:
                print(f"    capability: {capability}")
            for action in reachable["allowed_actions"]:
                print(f"    allowed action: {action}")

        return 0

    if as_json:
        _print_json(graph.to_dict())
        return 0

    print(
        f"{len(graph.nodes())} nodes, "
        f"{len(graph.edges())} edges"
    )
    print("agents:", sorted(
        {
            node.label
            for node in graph.nodes()
            if node.type == "agent"
        }
    ))
    print("capabilities:", sorted(
        {
            node.label
            for node in graph.nodes()
            if node.type == "capability"
        }
    ))
    print("hint: use --agent, --why <action>, --reach")

    return 0


def command_incident(
    artifact_path: str,
    *,
    title: str,
    summary: str,
    redact: bool,
    out: str,
) -> int:
    try:
        from firewall.artifact import artifact_from_path
        from firewall.incident import (
            create_incident_package,
            write_incident_package,
        )
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        package = create_incident_package(
            artifact,
            title=title,
            summary=summary,
            redact=redact,
        )
        write_incident_package(package, out)
    except Exception as exc:
        return _fail(f"incident package failed: {exc}")

    verification = package["verification"]
    print(f"created {out}")
    print(
        f"  verification: {verification['status']} "
        f"({len(verification['findings'])} findings)"
    )

    return 0


def command_redact(
    artifact_path: str,
    out: str,
) -> int:
    try:
        from firewall.artifact import (
            artifact_from_path,
            write_artifact,
        )
        from firewall.incident import redact_artifact
    except Exception as exc:
        return _fail(f"cannot load: {exc}")

    try:
        artifact = artifact_from_path(artifact_path)
        redacted = redact_artifact(artifact)
        write_artifact(redacted, out)
    except Exception as exc:
        return _fail(f"redaction failed: {exc}")

    print(f"wrote redacted {out}")

    return 0


# ======================================================================
# Entry point
# ======================================================================


def main(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    command = args.command

    if command == "init":
        return command_init(
            args.path
        )

    if command == "validate":
        return command_validate(
            args.path
        )

    if command == "inspect-token":
        return command_inspect_token(
            args.token
        )

    if command == "explain":
        return command_explain(
            args.path,
            fingerprint=args.fingerprint,
            event_type=args.event_type,
            as_json=args.as_json,
        )

    if command == "simulate":
        return command_simulate(
            args.cases,
            rules=args.rules,
            baseline=args.baseline,
            max_depth=args.max_depth,
            as_json=args.as_json,
        )

    if command == "record":
        return command_record(
            args.out,
            args.agent,
        )

    if command == "inspect":
        return command_inspect(
            args.artifact,
            as_json=args.as_json,
        )

    if command == "verify":
        return command_verify(
            args.artifact,
            expect_recorder=args.expect_recorder,
            as_json=args.as_json,
        )

    if command == "replay":
        return command_replay(
            args.artifact,
            rules=args.rules,
            limit=args.limit,
            as_json=args.as_json,
        )

    if command == "timeline":
        return command_timeline(
            args.artifact,
            as_json=args.as_json,
        )

    if command == "trajectory":
        return command_trajectory(
            args.artifact,
            as_json=args.as_json,
        )

    if command == "graph":
        return command_graph(
            args.artifact,
            agent=args.agent,
            why=args.why,
            reach=args.reach,
            as_json=args.as_json,
        )

    if command == "incident":
        if args.incident_command == "create":
            return command_incident(
                args.artifact,
                title=args.title,
                summary=args.summary,
                redact=args.redact,
                out=args.out,
            )

        parser.error(
            f"unknown incident command: {args.incident_command}"
        )
        return 2

    if command == "redact":
        return command_redact(
            args.artifact,
            args.out,
        )

    parser.error(
        f"unknown command: {command}"
    )

    return 2


# ======================================================================
# v1.9 network commands
# ======================================================================


def _v19():
    """Lazily import the v1.9 command handlers."""

    from firewall.cli_v19 import (
        command_attack_path,
        command_detect,
        command_network_correlate,
        command_network_graph,
        command_network_ingest,
        command_network_init,
        command_respond,
        command_simulate_network,
    )

    return {
        "network_init": command_network_init,
        "network_ingest": command_network_ingest,
        "network_graph": command_network_graph,
        "network_correlate": command_network_correlate,
        "detect": command_detect,
        "attack_path": command_attack_path,
        "simulate_network": command_simulate_network,
        "respond": command_respond,
    }


def build_parser_v19(parser) -> None:
    """Register the v1.9 subcommands on ``parser``."""

    subparsers = parser._firewall_subparsers

    # network
    network_parser = subparsers.add_parser(
        "network",
        help=(
            "Cross-agent security network over verified artifacts."
        ),
    )
    network_sub = network_parser.add_subparsers(
        dest="network_command",
        required=True,
    )

    network_init = network_sub.add_parser(
        "init",
        help="Create an empty network state file.",
    )
    network_init.add_argument(
        "--out",
        default="network.json",
        help="Network state output path.",
    )
    network_init.add_argument(
        "--note",
        default="",
        help="Optional note stored in the state file.",
    )

    network_ingest = network_sub.add_parser(
        "ingest",
        help="Verify and ingest .afw artifacts into the network.",
    )
    network_ingest.add_argument(
        "paths",
        nargs="+",
        help="Artifact files to ingest.",
    )
    network_ingest.add_argument(
        "--state",
        default="network.json",
        help="Network state file (created if missing).",
    )
    network_ingest.add_argument(
        "--out",
        default=None,
        help="Write state here instead of in place.",
    )
    network_ingest.add_argument(
        "--allow-failed",
        action="store_true",
        help="Ingest artifacts that fail verification.",
    )
    network_ingest.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    network_graph = network_sub.add_parser(
        "graph",
        help="Query the merged security network graph.",
    )
    network_graph.add_argument(
        "state",
        help="Network state file.",
    )
    network_graph.add_argument(
        "--agent",
        default=None,
        help="Agent to analyze.",
    )
    network_graph.add_argument(
        "--why",
        default=None,
        metavar="ACTION",
        help="Why can --agent perform ACTION?",
    )
    network_graph.add_argument(
        "--reach",
        action="store_true",
        help="What can --agent reach?",
    )
    network_graph.add_argument(
        "--who-can-reach",
        default=None,
        metavar="RESOURCE",
        help="Which agents can reach RESOURCE?",
    )
    network_graph.add_argument(
        "--shared",
        default=None,
        metavar="RESOURCE",
        help="Which of --agents share a path to RESOURCE?",
    )
    network_graph.add_argument(
        "--agents",
        default=None,
        help="Comma-separated agents for --shared.",
    )
    network_graph.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    network_correlate = network_sub.add_parser(
        "correlate",
        help="Show correlation bundles across ingested artifacts.",
    )
    network_correlate.add_argument(
        "state",
        help="Network state file.",
    )
    network_correlate.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    network_simulate = network_sub.add_parser(
        "simulate",
        help=(
            "Simulate a security scenario (compromised agent, stolen "
            "capability, policy change, ...) in an isolated workspace."
        ),
    )
    network_simulate.add_argument(
        "state",
        help="Network state file.",
    )
    network_simulate.add_argument(
        "scenario",
        help="Scenario JSON file.",
    )
    network_simulate.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # detect
    detect_parser = subparsers.add_parser(
        "detect",
        help="Run behavioral detections over the network.",
    )
    detect_parser.add_argument(
        "state",
        help="Network state file.",
    )
    detect_parser.add_argument(
        "--min-severity",
        default="low",
        choices=("low", "medium", "high", "critical"),
        help="Minimum severity to report.",
    )
    detect_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # attack-path
    attack_parser = subparsers.add_parser(
        "attack-path",
        help="Discover attack paths in the network.",
    )
    attack_parser.add_argument(
        "state",
        help="Network state file.",
    )
    attack_parser.add_argument(
        "--agent",
        default=None,
        help="Start agent for a shortest-path query.",
    )
    attack_parser.add_argument(
        "--to",
        default=None,
        metavar="TARGET",
        help="Target resource/capability.",
    )
    attack_parser.add_argument(
        "--summary",
        action="store_true",
        help="List sensitive resources recorded in the network.",
    )
    attack_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # respond
    respond_parser = subparsers.add_parser(
        "respond",
        help=(
            "Evaluate detections against a response policy and apply "
            "graduated responses (observe/warn/restrict/quarantine/"
            "contain)."
        ),
    )
    respond_parser.add_argument(
        "state",
        help="Network state file.",
    )
    respond_parser.add_argument(
        "--policy",
        default=None,
        dest="policy_path",
        help="Response policy JSON file.",
    )
    respond_parser.add_argument(
        "--rule",
        default=None,
        help="Only respond to this rule id.",
    )
    respond_parser.add_argument(
        "--min-severity",
        default=None,
        choices=("low", "medium", "high", "critical"),
        help="Minimum detection severity.",
    )
    respond_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )


def build_parser_v20(parser) -> None:
    """Register the v2.0 subcommands on ``parser``."""

    subparsers = parser._firewall_subparsers

    # identity
    identity_parser = subparsers.add_parser(
        "identity",
        help="Manage agent identities.",
    )
    identity_sub = identity_parser.add_subparsers(
        dest="identity_command",
        required=True,
    )

    identity_create = identity_sub.add_parser(
        "create",
        help="Create an agent identity.",
    )
    identity_create.add_argument("agent", help="Agent id.")
    identity_create.add_argument(
        "--registry",
        default="identities.json",
        help="Identity registry state file.",
    )
    identity_create.add_argument("--owner", default="")
    identity_create.add_argument("--environment", default="")
    identity_create.add_argument("--issuer", default="trusted-issuer")
    identity_create.add_argument("--parent", default=None)
    identity_create.add_argument(
        "--passphrase",
        default=None,
        help="Encrypt the stored private key with this passphrase.",
    )
    identity_create.add_argument("--json", action="store_true", dest="as_json")

    identity_show = identity_sub.add_parser(
        "show",
        help="Show identities in the registry.",
    )
    identity_show.add_argument("--registry", default="identities.json")
    identity_show.add_argument("--agent", default=None)
    identity_show.add_argument("--passphrase", default=None)
    identity_show.add_argument("--json", action="store_true", dest="as_json")

    identity_rotate = identity_sub.add_parser(
        "rotate",
        help="Rotate an identity key.",
    )
    identity_rotate.add_argument("agent")
    identity_rotate.add_argument("--registry", default="identities.json")
    identity_rotate.add_argument("--passphrase", default=None)
    identity_rotate.add_argument("--json", action="store_true", dest="as_json")

    identity_revoke = identity_sub.add_parser(
        "revoke",
        help="Revoke an identity.",
    )
    identity_revoke.add_argument("agent")
    identity_revoke.add_argument("--registry", default="identities.json")
    identity_revoke.add_argument("--reason", default="")
    identity_revoke.add_argument("--passphrase", default=None)
    identity_revoke.add_argument("--json", action="store_true", dest="as_json")

    # task
    task_parser = subparsers.add_parser(
        "task",
        help="Manage task-bound authority.",
    )
    task_sub = task_parser.add_subparsers(
        dest="task_command",
        required=True,
    )

    task_create = task_sub.add_parser(
        "create",
        help="Create a task for an agent.",
    )
    task_create.add_argument("agent")
    task_create.add_argument(
        "--registry", default="identities.json"
    )
    task_create.add_argument(
        "--state", default="tasks.json",
        help="Task registry state file.",
    )
    task_create.add_argument(
        "--permissions",
        default=None,
        help="JSON permissions map.",
    )
    task_create.add_argument("--passphrase", default=None)
    task_create.add_argument("--json", action="store_true", dest="as_json")

    task_delegate = task_sub.add_parser(
        "delegate",
        help="Delegate a task to another agent (narrowing).",
    )
    task_delegate.add_argument("task_id")
    task_delegate.add_argument("agent")
    task_delegate.add_argument(
        "--registry", default="identities.json"
    )
    task_delegate.add_argument(
        "--state", default="tasks.json"
    )
    task_delegate.add_argument(
        "--permissions", default=None, help="JSON grant map."
    )
    task_delegate.add_argument("--passphrase", default=None)
    task_delegate.add_argument("--json", action="store_true", dest="as_json")

    task_show = task_sub.add_parser(
        "show",
        help="List tasks.",
    )
    task_show.add_argument("--registry", default="identities.json")
    task_show.add_argument("--state", default="tasks.json")
    task_show.add_argument("--agent", default=None)
    task_show.add_argument("--passphrase", default=None)
    task_show.add_argument("--json", action="store_true", dest="as_json")

    # passport
    passport_parser = subparsers.add_parser(
        "passport",
        help="Agent security passports.",
    )
    passport_sub = passport_parser.add_subparsers(
        dest="passport_command",
        required=True,
    )
    passport_show = passport_sub.add_parser(
        "show",
        help="Build and show an agent's security passport.",
    )
    passport_show.add_argument("agent")
    passport_show.add_argument("--registry", default="identities.json")
    passport_show.add_argument("--out", default=None)
    passport_show.add_argument("--passphrase", default=None)
    passport_show.add_argument("--json", action="store_true", dest="as_json")

    passport_verify = passport_sub.add_parser(
        "verify",
        help="Verify a passport file.",
    )
    passport_verify.add_argument("passport")
    passport_verify.add_argument("--registry", default="identities.json")
    passport_verify.add_argument("--passphrase", default=None)
    passport_verify.add_argument("--json", action="store_true", dest="as_json")

    # attestation
    attest_parser = subparsers.add_parser(
        "attestation",
        help="Verify cryptographic attestations.",
    )
    attest_parser.add_argument("attestation", help="Attestation JSON file.")
    attest_parser.add_argument("--registry", default="identities.json")
    attest_parser.add_argument("--passphrase", default=None)
    attest_parser.add_argument("--json", action="store_true", dest="as_json")

    # provenance
    provenance_parser = subparsers.add_parser(
        "provenance",
        help="Agent supply-chain provenance.",
    )
    provenance_sub = provenance_parser.add_subparsers(
        dest="provenance_command",
        required=True,
    )
    prov_register = provenance_sub.add_parser(
        "register",
        help="Register a component.",
    )
    prov_register.add_argument("kind", choices=[
        "model", "tool", "mcp_server", "skill", "plugin",
        "package", "adapter", "configuration", "policy",
    ])
    prov_register.add_argument("name")
    prov_register.add_argument("--state", default="provenance.json")
    prov_register.add_argument("--version", default="")
    prov_register.add_argument("--source", default="")
    prov_register.add_argument("--integrity", default="")
    prov_register.add_argument("--dependencies", default=None)
    prov_register.add_argument("--json", action="store_true", dest="as_json")

    prov_trust = provenance_sub.add_parser(
        "trust",
        help="Trust / suspect / revoke a component.",
    )
    prov_trust.add_argument("action", choices=["trust", "suspect", "revoke"])
    prov_trust.add_argument("component_id")
    prov_trust.add_argument("--state", default="provenance.json")
    prov_trust.add_argument("--reason", default="")
    prov_trust.add_argument("--json", action="store_true", dest="as_json")

    prov_show = provenance_sub.add_parser(
        "show",
        help="List components.",
    )
    prov_show.add_argument("--state", default="provenance.json")
    prov_show.add_argument("--json", action="store_true", dest="as_json")

    prov_verify = provenance_sub.add_parser(
        "verify",
        help="Verify a component file against its integrity digest.",
    )
    prov_verify.add_argument("component_id")
    prov_verify.add_argument("file")
    prov_verify.add_argument("--state", default="provenance.json")
    prov_verify.add_argument("--json", action="store_true", dest="as_json")

    # posture
    posture_parser = subparsers.add_parser(
        "posture",
        help="Agent security posture.",
    )
    posture_parser.add_argument("state", help="Posture state JSON file.")
    posture_parser.add_argument("--agent", default=None)
    posture_parser.add_argument("--json", action="store_true", dest="as_json")

    # trust
    trust_parser = subparsers.add_parser(
        "trust",
        help="Cross-agent trust graph queries.",
    )
    trust_parser.add_argument("state", help="Network state file.")
    trust_parser.add_argument("--agent", default=None, help="what-can")
    trust_parser.add_argument("--who", default=None, help="who-can resource")
    trust_parser.add_argument("--delegated", default=None, help="who-delegated")
    trust_parser.add_argument("--changed", default=None, help="what-changed")
    trust_parser.add_argument("--radius", default=None, help="blast radius")
    trust_parser.add_argument("--json", action="store_true", dest="as_json")

    # lab
    lab_parser = subparsers.add_parser(
        "lab",
        help="Security Lab 2.0.",
    )
    lab_sub = lab_parser.add_subparsers(
        dest="lab_command",
        required=True,
    )
    lab_sweep = lab_sub.add_parser(
        "sweep",
        help="Evaluate the whole environment.",
    )
    lab_sweep.add_argument("state", help="Network state file.")
    lab_sweep.add_argument("--json", action="store_true", dest="as_json")

    lab_counter = lab_sub.add_parser(
        "counterfactual",
        help="Run a counterfactual scenario.",
    )
    lab_counter.add_argument("state")
    lab_counter.add_argument("--agent", required=True)
    lab_counter.add_argument("--kind", default="compromised_agent")
    lab_counter.add_argument("--title", default="scenario")
    lab_counter.add_argument("--added", default=None)
    lab_counter.add_argument("--removed", default=None)
    lab_counter.add_argument("--containment", default="none")
    lab_counter.add_argument("--json", action="store_true", dest="as_json")


def main_with_v20(argv=None) -> int:
    """v2.0 entry point: registers identity/task/passport/provenance/
    posture/trust/lab commands, then behaves exactly like v1.9 for every
    existing command."""

    parser = build_parser()
    build_parser_v19(parser)
    build_parser_v20(parser)

    args = parser.parse_args(argv)

    command = args.command

    from firewall.cli_v20 import (
        command_attest_verify,
        command_identity_create,
        command_identity_revoke,
        command_identity_rotate,
        command_identity_show,
        command_lab_counterfactual,
        command_lab_sweep,
        command_passport_show,
        command_passport_verify,
        command_posture_state,
        command_provenance_register,
        command_provenance_show,
        command_provenance_trust,
        command_provenance_verify,
        command_task_create,
        command_task_delegate,
        command_task_show,
        command_trust_query,
    )

    if command == "identity":
        if args.identity_command == "create":
            return command_identity_create(
                args.registry, args.agent,
                owner=args.owner,
                environment=args.environment,
                issuer=args.issuer,
                parent=args.parent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.identity_command == "show":
            return command_identity_show(
                args.registry,
                agent=args.agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.identity_command == "rotate":
            return command_identity_rotate(
                args.registry, args.agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.identity_command == "revoke":
            return command_identity_revoke(
                args.registry, args.agent,
                reason=args.reason,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        parser.error(f"unknown identity command: {args.identity_command}")
        return 2

    if command == "task":
        if args.task_command == "create":
            return command_task_create(
                args.registry, args.agent,
                state=args.state,
                permissions=args.permissions,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.task_command == "delegate":
            return command_task_delegate(
                args.registry, args.task_id, args.agent,
                state=args.state,
                permissions=args.permissions,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.task_command == "show":
            return command_task_show(
                args.registry,
                state=args.state,
                agent=args.agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        parser.error(f"unknown task command: {args.task_command}")
        return 2

    if command == "passport":
        if args.passport_command == "show":
            return command_passport_show(
                args.registry, args.agent,
                out=args.out,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.passport_command == "verify":
            return command_passport_verify(
                args.passport,
                args.registry,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        parser.error(f"unknown passport command: {args.passport_command}")
        return 2

    if command == "attestation":
        return command_attest_verify(
            args.attestation,
            args.registry,
            passphrase=args.passphrase,
            as_json=args.as_json,
        )

    if command == "provenance":
        if args.provenance_command == "register":
            return command_provenance_register(
                args.state, args.kind, args.name,
                version=args.version,
                source=args.source,
                integrity=args.integrity,
                dependencies=args.dependencies,
                as_json=args.as_json,
            )
        if args.provenance_command == "trust":
            return command_provenance_trust(
                args.state, args.component_id,
                reason=args.reason,
                action=args.action,
                as_json=args.as_json,
            )
        if args.provenance_command == "show":
            return command_provenance_show(
                args.state,
                as_json=args.as_json,
            )
        if args.provenance_command == "verify":
            return command_provenance_verify(
                args.state, args.component_id, args.file,
                as_json=args.as_json,
            )
        parser.error(f"unknown provenance command: {args.provenance_command}")
        return 2

    if command == "posture":
        return command_posture_state(
            args.state,
            agent=args.agent,
            as_json=args.as_json,
        )

    if command == "trust":
        return command_trust_query(
            args.state,
            agent=args.agent,
            who=args.who,
            delegated=args.delegated,
            changed=args.changed,
            radius=args.radius,
            as_json=args.as_json,
        )

    if command == "lab":
        if args.lab_command == "sweep":
            return command_lab_sweep(
                args.state,
                as_json=args.as_json,
            )
        if args.lab_command == "counterfactual":
            return command_lab_counterfactual(
                args.state,
                agent=args.agent,
                kind=args.kind,
                title=args.title,
                added=args.added,
                removed=args.removed,
                containment=args.containment,
                as_json=args.as_json,
            )
        parser.error(f"unknown lab command: {args.lab_command}")
        return 2

    return main_with_v19(argv)


def main_with_v19(argv=None) -> int:
    """v1.9 entry point: registers the network commands, then behaves
    exactly like the v1.8 CLI for every existing command."""

    parser = build_parser()
    build_parser_v19(parser)

    args = parser.parse_args(argv)

    if args.command == "network":
        handlers = _v19()
        if args.network_command == "init":
            return handlers["network_init"](args.out, args.note)
        if args.network_command == "ingest":
            return handlers["network_ingest"](
                args.state,
                args.paths,
                out=args.out,
                allow_failed=args.allow_failed,
                as_json=args.as_json,
            )
        if args.network_command == "graph":
            return handlers["network_graph"](
                args.state,
                agent=args.agent,
                why=args.why,
                reach=args.reach,
                who_can_reach=args.who_can_reach,
                shared=args.shared,
                agents=args.agents,
                as_json=args.as_json,
            )
        if args.network_command == "correlate":
            return handlers["network_correlate"](
                args.state,
                as_json=args.as_json,
            )
        if args.network_command == "simulate":
            return handlers["simulate_network"](
                args.state,
                args.scenario,
                as_json=args.as_json,
            )
        parser.error(f"unknown network command: {args.network_command}")
        return 2

    if args.command == "detect":
        return _v19()["detect"](
            args.state,
            min_severity=args.min_severity,
            as_json=args.as_json,
        )

    if args.command == "attack-path":
        return _v19()["attack_path"](
            args.state,
            agent=args.agent,
            to=args.to,
            summary=args.summary,
            as_json=args.as_json,
        )

    if args.command == "respond":
        return _v19()["respond"](
            args.state,
            rule=args.rule,
            severity=args.min_severity,
            policy_path=args.policy_path,
            as_json=args.as_json,
        )

    return main(argv)


# ======================================================================
# v2.1 commands
# ======================================================================


def build_parser_v21(parser) -> None:
    """Register the v2.1 subcommands on ``parser``."""

    subparsers = parser._firewall_subparsers

    # defense (defense mesh)
    defense_parser = subparsers.add_parser(
        "defense",
        help="Real-time defense mesh: evaluate, quarantine, recover, re-enter.",
    )
    defense_sub = defense_parser.add_subparsers(
        dest="defense_command", required=True
    )
    d_eval = defense_sub.add_parser("evaluate", help="Evaluate one agent.")
    d_eval.add_argument("agent")
    d_eval.add_argument("--registry", default="identities.json")
    d_eval.add_argument("--state", default="mesh.json",
                        help="Persistent mesh state file.")
    d_eval.add_argument("--passphrase", default=None)
    d_eval.add_argument("--json", action="store_true", dest="as_json")

    d_quar = defense_sub.add_parser("quarantine", help="Quarantine an agent.")
    d_quar.add_argument("agent")
    d_quar.add_argument("--registry", default="identities.json")
    d_quar.add_argument("--state", default="mesh.json")
    d_quar.add_argument("--reason", required=True)
    d_quar.add_argument("--actor", default="cli")
    d_quar.add_argument("--passphrase", default=None)
    d_quar.add_argument("--json", action="store_true", dest="as_json")

    d_rec = defense_sub.add_parser("recover", help="Begin mesh recovery.")
    d_rec.add_argument("agent")
    d_rec.add_argument("--registry", default="identities.json")
    d_rec.add_argument("--state", default="mesh.json")
    d_rec.add_argument("--reason", required=True)
    d_rec.add_argument("--actor", default="cli")
    d_rec.add_argument("--passphrase", default=None)
    d_rec.add_argument("--json", action="store_true", dest="as_json")

    d_ren = defense_sub.add_parser("reenter", help="Re-enter an agent.")
    d_ren.add_argument("agent")
    d_ren.add_argument("--registry", default="identities.json")
    d_ren.add_argument("--state", default="mesh.json")
    d_ren.add_argument("--reason", required=True)
    d_ren.add_argument("--actor", default="cli")
    d_ren.add_argument("--passphrase", default=None)
    d_ren.add_argument("--json", action="store_true", dest="as_json")

    d_state = defense_sub.add_parser("state", help="Show mesh state.")
    d_state.add_argument("--registry", default="identities.json")
    d_state.add_argument("--state", default="mesh.json")
    d_state.add_argument("--agent", default=None)
    d_state.add_argument("--passphrase", default=None)
    d_state.add_argument("--json", action="store_true", dest="as_json")

    # delegate (a2a zero trust)
    delegate_parser = subparsers.add_parser(
        "delegate",
        help="Agent-to-agent zero trust: establish, grant, revoke, authorize.",
    )
    delegate_sub = delegate_parser.add_subparsers(
        dest="delegate_command", required=True
    )
    dl_est = delegate_sub.add_parser("establish", help="Establish a relationship.")
    dl_est.add_argument("--registry", default="identities.json")
    dl_est.add_argument("--state", default="a2a.json")
    dl_est.add_argument("--initiator", required=True)
    dl_est.add_argument("--responder", required=True)
    dl_est.add_argument("--permissions", default=None)
    dl_est.add_argument("--ttl", type=float, default=None)
    dl_est.add_argument("--passphrase", default=None)
    dl_est.add_argument("--json", action="store_true", dest="as_json")

    dl_grant = delegate_sub.add_parser("grant", help="Delegate a relationship.")
    dl_grant.add_argument("--registry", default="identities.json")
    dl_grant.add_argument("--state", default="a2a.json")
    dl_grant.add_argument("--relationship", required=True)
    dl_grant.add_argument("--responder", required=True)
    dl_grant.add_argument("--permissions", default=None)
    dl_grant.add_argument("--passphrase", default=None)
    dl_grant.add_argument("--json", action="store_true", dest="as_json")

    dl_rev = delegate_sub.add_parser("revoke", help="Revoke a relationship.")
    dl_rev.add_argument("--registry", default="identities.json")
    dl_rev.add_argument("--state", default="a2a.json")
    dl_rev.add_argument("--relationship", required=True)
    dl_rev.add_argument("--reason", required=True)
    dl_rev.add_argument("--passphrase", default=None)
    dl_rev.add_argument("--json", action="store_true", dest="as_json")

    dl_down = delegate_sub.add_parser("teardown", help="Tear down trust.")
    dl_down.add_argument("--registry", default="identities.json")
    dl_down.add_argument("--state", default="a2a.json")
    dl_down.add_argument("--a", required=True)
    dl_down.add_argument("--b", required=True)
    dl_down.add_argument("--reason", required=True)
    dl_down.add_argument("--passphrase", default=None)
    dl_down.add_argument("--json", action="store_true", dest="as_json")

    dl_auth = delegate_sub.add_parser("authorize", help="Cross-agent decision.")
    dl_auth.add_argument("--registry", default="identities.json")
    dl_auth.add_argument("--state", default="a2a.json")
    dl_auth.add_argument("--actor", required=True)
    dl_auth.add_argument("--target", required=True)
    dl_auth.add_argument("--action", required=True)
    dl_auth.add_argument("--request", default=None)
    dl_auth.add_argument("--passphrase", default=None)
    dl_auth.add_argument("--json", action="store_true", dest="as_json")

    dl_graph = delegate_sub.add_parser("graph", help="Show the a2a trust graph.")
    dl_graph.add_argument("--registry", default="identities.json")
    dl_graph.add_argument("--state", default="a2a.json")
    dl_graph.add_argument("--passphrase", default=None)
    dl_graph.add_argument("--json", action="store_true", dest="as_json")

    # capability (capability firewall 2.0)
    capability_parser = subparsers.add_parser(
        "capability",
        help="Capability Firewall 2.0 policies.",
    )
    capability_sub = capability_parser.add_subparsers(
        dest="capability_command", required=True
    )
    cap_eval = capability_sub.add_parser("eval", help="Evaluate a request.")
    cap_eval.add_argument("policy", help="Capability2 JSON policy file.")
    cap_eval.add_argument("request", help="JSON request object.")
    cap_eval.add_argument("--json", action="store_true", dest="as_json")

    cap_att = capability_sub.add_parser("attenuate", help="Narrow a policy.")
    cap_att.add_argument("policy")
    cap_att.add_argument("--out", required=True)
    cap_att.add_argument("--narrowing", default=None)
    cap_att.add_argument("--json", action="store_true", dest="as_json")

    cap_del = capability_sub.add_parser("delegate", help="Delegate a policy.")
    cap_del.add_argument("policy")
    cap_del.add_argument("--out", required=True)
    cap_del.add_argument("--narrowing", default=None)
    cap_del.add_argument("--json", action="store_true", dest="as_json")

    # attack-graph
    ag_parser = subparsers.add_parser(
        "attack-graph",
        help="Autonomous attack-path engine.",
    )
    ag_sub = ag_parser.add_subparsers(
        dest="attackgraph_command", required=True
    )
    ag_build = ag_sub.add_parser("build", help="Build from a network state.")
    ag_build.add_argument("state", help="Network state file.")
    ag_build.add_argument("--out", default="attack-graph.json")
    ag_build.add_argument("--json", action="store_true", dest="as_json")

    ag_paths = ag_sub.add_parser("paths", help="Paths to a target.")
    ag_paths.add_argument("graph", help="Attack graph JSON file.")
    ag_paths.add_argument("--target", required=True)
    ag_paths.add_argument("--max-hops", type=int, default=8)
    ag_paths.add_argument("--json", action="store_true", dest="as_json")

    ag_find = ag_sub.add_parser("findings", help="Escalation paths + chokepoints.")
    ag_find.add_argument("graph")
    ag_find.add_argument("--json", action="store_true", dest="as_json")

    ag_sum = ag_sub.add_parser("summarize", help="Graph overview.")
    ag_sum.add_argument("graph")
    ag_sum.add_argument("--json", action="store_true", dest="as_json")

    # twin
    twin_parser = subparsers.add_parser(
        "twin",
        help="Security digital twin counterfactuals.",
    )
    twin_parser.add_argument("state", help="Network state file.")
    twin_parser.add_argument("--kind", required=True,
        choices=("compromised_agent", "revoked_capability",
                 "untrusted_tool", "delegated_authority",
                 "exposed_credential"))
    twin_parser.add_argument("--agent", default=None)
    twin_parser.add_argument("--capability", default=None)
    twin_parser.add_argument("--tool", default=None)
    twin_parser.add_argument("--grantor", default=None)
    twin_parser.add_argument("--grantee", default=None)
    twin_parser.add_argument("--credential", default=None)
    twin_parser.add_argument("--json", action="store_true", dest="as_json")

    # evidence
    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Cryptographic evidence graph.",
    )
    evidence_sub = evidence_parser.add_subparsers(
        dest="evidence_command", required=True
    )
    ev_append = evidence_sub.add_parser("append", help="Append a signed event.")
    ev_append.add_argument("--state", default="evidence.json")
    ev_append.add_argument("--kind", required=True,
        choices=("observed", "inference", "prediction", "simulation", "unknown"))
    ev_append.add_argument("--subject", required=True)
    ev_append.add_argument("--type", dest="event_type", required=True)
    ev_append.add_argument("--payload", default=None)
    ev_append.add_argument("--registry", default=None)
    ev_append.add_argument("--signer-agent", default=None)
    ev_append.add_argument("--passphrase", default=None)
    ev_append.add_argument("--json", action="store_true", dest="as_json")

    ev_verify = evidence_sub.add_parser("verify", help="Verify the chain.")
    ev_verify.add_argument("--state", default="evidence.json")
    ev_verify.add_argument("--registry", default=None)
    ev_verify.add_argument("--signer-agent", default=None)
    ev_verify.add_argument("--passphrase", default=None)
    ev_verify.add_argument("--json", action="store_true", dest="as_json")

    ev_timeline = evidence_sub.add_parser("timeline", help="Replay a timeline.")
    ev_timeline.add_argument("--state", default="evidence.json")
    ev_timeline.add_argument("--subject", required=True)
    ev_timeline.add_argument("--registry", default=None)
    ev_timeline.add_argument("--signer-agent", default=None)
    ev_timeline.add_argument("--passphrase", default=None)
    ev_timeline.add_argument("--json", action="store_true", dest="as_json")

    ev_promote = evidence_sub.add_parser("promote", help="Explicit promotion.")
    ev_promote.add_argument("--state", default="evidence.json")
    ev_promote.add_argument("--event-id", required=True)
    ev_promote.add_argument("--reason", required=True)
    ev_promote.add_argument("--registry", default=None)
    ev_promote.add_argument("--signer-agent", default=None)
    ev_promote.add_argument("--passphrase", default=None)
    ev_promote.add_argument("--json", action="store_true", dest="as_json")

    # immune
    immune_parser = subparsers.add_parser(
        "immune",
        help="Agent immune system (OBSERVE..VERIFY loop).",
    )
    immune_sub = immune_parser.add_subparsers(
        dest="immune_command", required=True
    )
    imm_demo = immune_sub.add_parser("demo", help="Run a demo cycle.")
    imm_demo.add_argument("--policy", default=None)
    imm_demo.add_argument("--json", action="store_true", dest="as_json")
    imm_state = immune_sub.add_parser("state", help="Show the loop contract.")
    imm_state.add_argument("--json", action="store_true", dest="as_json")

    # research
    research_parser = subparsers.add_parser(
        "research",
        help="Security Research Lab 3.0.",
    )
    research_sub = research_parser.add_subparsers(
        dest="research_command", required=True
    )
    r_run = research_sub.add_parser("run", help="Run attack scenarios.")
    r_run.add_argument("--scenario", default=None)
    r_run.add_argument("--json", action="store_true", dest="as_json")
    r_prop = research_sub.add_parser("properties", help="Property tests.")
    r_prop.add_argument("--json", action="store_true", dest="as_json")
    r_rep = research_sub.add_parser("report", help="Full report.")
    r_rep.add_argument("--out", default=None)
    r_rep.add_argument("--json", action="store_true", dest="as_json")

    # recover
    recover_parser = subparsers.add_parser(
        "recover",
        help="Mesh recovery + re-entry.",
    )
    recover_parser.add_argument("agent")
    recover_parser.add_argument("--registry", default="identities.json")
    recover_parser.add_argument("--state", default="mesh.json")
    recover_parser.add_argument("--reason", required=True)
    recover_parser.add_argument("--actor", default="cli")
    recover_parser.add_argument("--passphrase", default=None)
    recover_parser.add_argument("--json", action="store_true", dest="as_json")


def main_with_v21(argv=None) -> int:
    """v2.1 entry point: registers the v2.1 commands, then behaves
    exactly like the v2.0 CLI for every existing command."""

    parser = build_parser()
    build_parser_v19(parser)
    build_parser_v20(parser)
    build_parser_v21(parser)

    args = parser.parse_args(argv)

    command = args.command

    from firewall.cli_v21 import (
        command_attackgraph_build,
        command_attackgraph_findings,
        command_attackgraph_paths,
        command_attackgraph_summarize,
        command_capability_attenuate,
        command_capability_delegate,
        command_capability_eval,
        command_defense_evaluate,
        command_defense_quarantine,
        command_defense_recover,
        command_defense_reenter,
        command_defense_state,
        command_delegate_authorize,
        command_delegate_establish,
        command_delegate_grant,
        command_delegate_graph,
        command_delegate_revoke,
        command_delegate_teardown,
        command_evidence_append,
        command_evidence_promote,
        command_evidence_timeline,
        command_evidence_verify,
        command_immune_demo,
        command_immune_state,
        command_recover_mesh,
        command_research_properties,
        command_research_report,
        command_research_run,
        command_twin_counterfactual,
    )

    if command == "defense":
        if args.defense_command == "evaluate":
            return command_defense_evaluate(
                args.registry, args.agent,
                state_path=args.state,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.defense_command == "quarantine":
            return command_defense_quarantine(
                args.registry, args.agent,
                state_path=args.state,
                reason=args.reason, actor=args.actor,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.defense_command == "recover":
            return command_defense_recover(
                args.registry, args.agent,
                state_path=args.state,
                reason=args.reason, actor=args.actor,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.defense_command == "reenter":
            return command_defense_reenter(
                args.registry, args.agent,
                state_path=args.state,
                reason=args.reason, actor=args.actor,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.defense_command == "state":
            return command_defense_state(
                args.registry,
                state_path=args.state,
                agent=args.agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        parser.error(f"unknown defense command: {args.defense_command}")
        return 2

    if command == "delegate":
        if args.delegate_command == "establish":
            return command_delegate_establish(
                args.registry, args.state,
                initiator=args.initiator, responder=args.responder,
                permissions=args.permissions, ttl=args.ttl,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.delegate_command == "grant":
            return command_delegate_grant(
                args.registry, args.state,
                relationship=args.relationship, responder=args.responder,
                permissions=args.permissions,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.delegate_command == "revoke":
            return command_delegate_revoke(
                args.registry, args.state,
                relationship=args.relationship, reason=args.reason,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.delegate_command == "teardown":
            return command_delegate_teardown(
                args.registry, args.state,
                a=args.a, b=args.b, reason=args.reason,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.delegate_command == "authorize":
            return command_delegate_authorize(
                args.registry, args.state,
                actor=args.actor, target=args.target, action=args.action,
                request=args.request,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        if args.delegate_command == "graph":
            return command_delegate_graph(
                args.registry, args.state,
                passphrase=args.passphrase, as_json=args.as_json,
            )
        parser.error(f"unknown delegate command: {args.delegate_command}")
        return 2

    if command == "capability":
        if args.capability_command == "eval":
            return command_capability_eval(
                args.policy, args.request, as_json=args.as_json,
            )
        if args.capability_command == "attenuate":
            return command_capability_attenuate(
                args.policy,
                out=args.out, narrowing=args.narrowing,
                as_json=args.as_json,
            )
        if args.capability_command == "delegate":
            return command_capability_delegate(
                args.policy,
                out=args.out, narrowing=args.narrowing,
                as_json=args.as_json,
            )
        parser.error(f"unknown capability command: {args.capability_command}")
        return 2

    if command == "attack-graph":
        if args.attackgraph_command == "build":
            return command_attackgraph_build(
                args.state, out=args.out, as_json=args.as_json,
            )
        if args.attackgraph_command == "paths":
            return command_attackgraph_paths(
                args.graph,
                target=args.target, max_hops=args.max_hops,
                as_json=args.as_json,
            )
        if args.attackgraph_command == "findings":
            return command_attackgraph_findings(
                args.graph, as_json=args.as_json,
            )
        if args.attackgraph_command == "summarize":
            return command_attackgraph_summarize(
                args.graph, as_json=args.as_json,
            )
        parser.error(f"unknown attack-graph command: {args.attackgraph_command}")
        return 2

    if command == "twin":
        return command_twin_counterfactual(
            args.state,
            kind=args.kind,
            agent=args.agent,
            capability=args.capability,
            tool=args.tool,
            grantor=args.grantor,
            grantee=args.grantee,
            credential=args.credential,
            as_json=args.as_json,
        )

    if command == "evidence":
        if args.evidence_command == "append":
            return command_evidence_append(
                args.state,
                kind=args.kind,
                subject=args.subject,
                event_type=args.event_type,
                payload=args.payload,
                registry_path=args.registry,
                signer_agent=args.signer_agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.evidence_command == "verify":
            return command_evidence_verify(
                args.state,
                registry_path=args.registry,
                signer_agent=args.signer_agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.evidence_command == "timeline":
            return command_evidence_timeline(
                args.state,
                subject=args.subject,
                registry_path=args.registry,
                signer_agent=args.signer_agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        if args.evidence_command == "promote":
            return command_evidence_promote(
                args.state,
                event_id=args.event_id,
                reason=args.reason,
                registry_path=args.registry,
                signer_agent=args.signer_agent,
                passphrase=args.passphrase,
                as_json=args.as_json,
            )
        parser.error(f"unknown evidence command: {args.evidence_command}")
        return 2

    if command == "immune":
        if args.immune_command == "demo":
            return command_immune_demo(
                args.policy, as_json=args.as_json,
            )
        if args.immune_command == "state":
            return command_immune_state(as_json=args.as_json)
        parser.error(f"unknown immune command: {args.immune_command}")
        return 2

    if command == "research":
        if args.research_command == "run":
            return command_research_run(
                args.scenario, as_json=args.as_json,
            )
        if args.research_command == "properties":
            return command_research_properties(as_json=args.as_json)
        if args.research_command == "report":
            return command_research_report(
                args.out, as_json=args.as_json,
            )
        parser.error(f"unknown research command: {args.research_command}")
        return 2

    if command == "recover":
        return command_recover_mesh(
            args.registry, args.agent,
            state_path=args.state,
            reason=args.reason, actor=args.actor,
            passphrase=args.passphrase, as_json=args.as_json,
        )

    return main_with_v20(argv)


if __name__ == "__main__":
    raise SystemExit(
        main_with_v21()
    )
