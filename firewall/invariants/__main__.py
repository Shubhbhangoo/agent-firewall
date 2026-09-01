"""``python -m firewall.invariants`` -- run the invariant suite from CI.

What this can and cannot establish is the whole point of the interface,
so it is stated here rather than left to be discovered from an exit code.

Five of the eleven invariants are claims about live state: a delegation
edge, an attenuation, a revocation, an applied policy transformation, a
simulation that ran. A fresh checkout has none, so those report
``UNVERIFIABLE``, and :attr:`InvariantReport.holds` is false. That is not
this command failing to do its job -- it is the suite refusing to claim a
system is sound when most of it was never examined. Exercising them needs
an SDK that has been used, which is what
``tests/test_v2_2_invariants.py`` does; this command is the part that can
run against source alone.

So the exit code distinguishes three outcomes rather than two:

* ``0`` -- every invariant that could be checked holds.
* ``1`` -- an invariant is **violated**. A security defect.
* ``2`` -- nothing is violated, but something could not be established,
  and ``--strict`` was given.

Without ``--strict`` an unverifiable result is reported and exits 0, so
a source-only CI job can gate on the three structural invariants -- a
subsystem constructing a verdict, a new reader of the live capability
registry, a second provenance vocabulary -- without every run failing
for lack of a running system. With ``--strict`` the command is exactly
:func:`firewall.invariants.assert_all`: unverifiable is not passing.

This command decides nothing. It reads source text and, if handed one,
live state, and prints findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from firewall.invariants.model import InvariantStatus
from firewall.invariants.registry import INVARIANTS, check_all

EXIT_OK = 0
EXIT_VIOLATED = 1
EXIT_UNVERIFIABLE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m firewall.invariants",
        description=(
            "Check the eleven v2.2 security invariants against this "
            "source tree. State-dependent invariants report "
            "unverifiable without a running system."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "treat unverifiable as failure (exit 2), matching "
            "assert_all"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full report as JSON instead of text",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print each invariant's statement and exit",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)

    if args.list:
        for entry in INVARIANTS:
            state = " (needs live state)" if entry.needs_state else ""
            print(f"{entry.name}{state}\n    {entry.statement}\n")
        return EXIT_OK

    report = check_all()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.summary())
        if report.unverifiable and not args.strict:
            print(
                "\nUnverifiable is not a pass. These need an exercised "
                "SDK, which the test suite provides:"
            )
            for item in report.unverifiable:
                print(f"  {item.name}")

    if report.violations:
        return EXIT_VIOLATED

    if report.unverifiable and args.strict:
        return EXIT_UNVERIFIABLE

    # Belt and braces: a status this module does not know about must not
    # be read as success.
    for item in report.results:
        if item.status not in (
            InvariantStatus.HOLDS,
            InvariantStatus.UNVERIFIABLE,
        ):
            return EXIT_VIOLATED

    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - process entry point
    sys.exit(main())
