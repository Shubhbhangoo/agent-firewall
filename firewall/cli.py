from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

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

    return parser


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

    print(
        json.dumps(
            capability.to_dict(),
            indent=2,
            sort_keys=True,
        )
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
            print(
                json.dumps(
                    [
                        _event_to_dict(
                            event
                        )
                        for event in events
                    ],
                    indent=2,
                    sort_keys=True,
                )
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


def main(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    if args.command == "init":
        return command_init(
            args.path
        )

    if args.command == "validate":
        return command_validate(
            args.path
        )

    if args.command == "inspect-token":
        return command_inspect_token(
            args.token
        )

    if args.command == "explain":
        return command_explain(
            args.path,
            fingerprint=args.fingerprint,
            event_type=args.event_type,
            as_json=args.as_json,
        )

    parser.error(
        f"unknown command: {args.command}"
    )

    return 2


if __name__ == "__main__":
    raise SystemExit(
        main()
    )