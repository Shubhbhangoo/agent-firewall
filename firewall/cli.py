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


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
