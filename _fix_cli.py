"""Fix CLI wiring: subparsers access, simulate name conflict."""

import io

# 1. Store subparsers on the parser in build_parser.
path = "firewall/cli.py"
source = io.open(path, encoding="utf-8").read()

old = """    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    init_parser = subparsers.add_parser("""

new = """    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Kept so the v1.9 command registrars can attach new subcommands
    # without re-creating the (single) subparsers action.
    parser._firewall_subparsers = subparsers

    init_parser = subparsers.add_parser("""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 2. build_parser_v19: use parser._firewall_subparsers; move simulate
#    under network to avoid the v1.8 name conflict.
old = """    subparsers = parser._subparsers

    # network
    network_parser = subparsers.add_parser("""

new = """    subparsers = parser._firewall_subparsers

    # network
    network_parser = subparsers.add_parser("""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 3. Move the simulate-scenario parser under network.
old = """    # simulate
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

    # respond"""

new = """    # respond"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 4. Add network simulate parser after network_correlate.
old = """    network_correlate.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # detect"""

new = """    network_correlate.add_argument(
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
        "scenario",
        help="Scenario JSON file.",
    )
    network_simulate.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    # detect"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 5. Wire network simulate in main_with_v19.
old = """        if args.network_command == "correlate":
            return handlers["network_correlate"](
                args.state,
                as_json=args.as_json,
            )
        parser.error(f"unknown network command: {args.network_command}")
        return 2"""

new = """        if args.network_command == "correlate":
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
        return 2"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 6. Remove the top-level simulate dispatch (no longer registered).
old = """    if args.command == "simulate":
        return _v19()["simulate_network"](
            args.state,
            args.scenario,
            as_json=args.as_json,
        )

    if args.command == "respond":"""

new = """    if args.command == "respond":"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("patched cli.py wiring")
