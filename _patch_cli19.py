"""Add to_json to ScenarioReport; wire v1.9 CLI into cli.py."""

import io

# 1. ScenarioReport.to_json
path = "firewall/network/simulator.py"
source = io.open(path, encoding="utf-8").read()

old = """    def text(self) -> str:
        lines = [
            f"scenario: {self.scenario.get('title')} "
            f"({self.scenario.get('kind')})","""

new = """    def to_json(self, *, indent: int = 2) -> str:
        import json

        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )

    def text(self) -> str:
        lines = [
            f"scenario: {self.scenario.get('title')} "
            f"({self.scenario.get('kind')})","""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("added ScenarioReport.to_json")

# 2. Wire v1.9 commands into cli.py.
path = "firewall/cli.py"
source = io.open(path, encoding="utf-8").read()

# 2a. Import the v1.9 handlers lazily inside main() -- no import cycle.
old = """if __name__ == "__main__":
    raise SystemExit(
        main()
    )"""

new = """# ======================================================================
# v1.9 network commands
# ======================================================================


def _v19():
    \"\"\"Lazily import the v1.9 command handlers.\"\"\"

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
    \"\"\"Register the v1.9 subcommands on ``parser``.\"\"\"

    subparsers = parser._subparsers

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

    # simulate
    simulate_parser = subparsers.add_parser(
        "simulate",
        help=(
            "Simulate a security scenario (compromised agent, stolen "
            "capability, policy change, ...) in an isolated workspace."
        ),
    )
    simulate_parser.add_argument(
        "state",
        help="Network state file.",
    )
    simulate_parser.add_argument(
        "scenario",
        help="Scenario JSON file.",
    )
    simulate_parser.add_argument(
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


def main_with_v19(argv=None) -> int:
    \"\"\"v1.9 entry point: registers the network commands, then behaves
    exactly like the v1.8 CLI for every existing command.\"\"\"

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

    if args.command == "simulate":
        return _v19()["simulate_network"](
            args.state,
            args.scenario,
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


if __name__ == "__main__":
    raise SystemExit(
        main_with_v19()
    )"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("wired v1.9 CLI")
