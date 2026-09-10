"""Run the full pytest suite in balanced shards.

The suite is ~4,800 tests and takes ~16 minutes on this machine, which is
longer than a single shell command may run. This tool splits it into shards
that can be run one at a time, without adding a dependency on
pytest-xdist / pytest-shard (neither is installed, and the suite is not
safe to parallelise in one process tree -- several tests bind fixed ports
and write shared store paths).

Sharding is by test *file*, weighted by collected test count, largest
first into the least-loaded shard. Files are never split, so a shard is
just a list of paths handed to pytest. That keeps the partition stable
for a given tree and reproducible between runs.

Usage
-----
    # plan shards (writes _shards/shard_N.txt and prints the partition)
    python run_shards.py plan [--shards 6]

    # run one shard (writes _shards/shard_N.log, exits with pytest's code)
    python run_shards.py run 3

    # extra pytest args are forwarded
    python run_shards.py run 3 --durations=12

    # run every shard sequentially (writes _shards/SUMMARY.txt)
    python run_shards.py all

Exit codes: 0 = all selected tests passed, 1 = failures, 2 = collection
error or usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SHARD_DIR = ROOT / "_shards"
PLAN_FILE = SHARD_DIR / "plan.json"

# Lines like "tests/test_v1_policy.py::TestX::test_y" from `pytest -q
# --collect-only`, plus the trailing "4799 tests collected in 5.17s".
NODE_LINE = re.compile(r"^(?P<path>[^:]+\.py)::(?P<rest>.+)$")
COLLECTED = re.compile(r"^(?P<n>\d+) tests? collected")

PYTEST = [sys.executable, "-m", "pytest"]


def _out(*parts: object) -> None:
    print(*parts, flush=True)


def collect_counts() -> dict[str, int]:
    """Return {relative test file path: number of collected tests}."""
    proc = subprocess.run(
        PYTEST + ["--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 5):  # 5 == no tests collected
        sys.stderr.write(proc.stdout[-4000:])
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(2)

    counts: dict[str, int] = {}
    total = None
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        m = COLLECTED.match(line)
        if m:
            total = int(m.group("n"))
            continue
        m = NODE_LINE.match(line)
        if m:
            path = m.group("path").replace("\\", "/")
            counts[path] = counts.get(path, 0) + 1

    if not counts:
        sys.stderr.write("no tests collected\n" + proc.stdout[-2000:])
        raise SystemExit(2)

    got = sum(counts.values())
    if total is not None and total != got:
        # Collection lines can be truncated for very long node ids; the
        # weighted partition would then be wrong, so say so loudly.
        _out(f"warning: pytest reported {total} tests, parsed {got} node ids")
    return counts


def _plan(counts: dict[str, int], shards: int) -> list[list[str]]:
    """Greedy largest-first partition of files into `shards` buckets."""
    buckets: list[list[str]] = [[] for _ in range(shards)]
    loads = [0] * shards
    for path, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        i = loads.index(min(loads))
        buckets[i].append(path)
        loads[i] += n
    for bucket in buckets:
        bucket.sort()
    return buckets


def write_plan(shards: int) -> list[list[str]]:
    counts = collect_counts()
    buckets = _plan(counts, shards)
    SHARD_DIR.mkdir(exist_ok=True)

    plan = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": sum(counts.values()),
        "shards": [
            {"index": i, "files": bucket, "tests": sum(counts[f] for f in bucket)}
            for i, bucket in enumerate(buckets, start=1)
        ],
    }
    PLAN_FILE.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    for shard in plan["shards"]:
        (SHARD_DIR / f"shard_{shard['index']}.txt").write_text(
            "\n".join(shard["files"]) + "\n", encoding="utf-8"
        )

    _out(f"collected {plan['total_tests']} tests over "
         f"{len(counts)} files -> {shards} shards")
    for shard in plan["shards"]:
        _out(f"  shard {shard['index']}: {shard['tests']:5d} tests, "
             f"{len(shard['files'])} files")
    return buckets


def load_plan() -> list[list[str]]:
    if not PLAN_FILE.exists():
        raise SystemExit(2)
    plan = json.loads(PLAN_FILE.read_text(encoding="utf-8"))
    return [list(s["files"]) for s in plan["shards"]]


def _result_line(log: Path) -> str:
    text = log.read_text(encoding="utf-8", errors="replace")
    for raw in reversed(text.splitlines()):
        line = raw.strip()
        if "passed" in line or "failed" in line or "error" in line:
            return line
    return "no pytest summary line"


def run_shard(index: int, buckets: list[list[str]],
              extra: tuple[str, ...] = ()) -> int:
    if not 1 <= index <= len(buckets):
        raise SystemExit(2)
    files = buckets[index - 1]
    log = SHARD_DIR / f"shard_{index}.log"
    started = time.time()
    with log.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(
            PYTEST + ["-q", "-p", "no:cacheprovider", *extra, *files],
            cwd=str(ROOT),
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
    elapsed = time.time() - started
    summary = _result_line(log)
    _out(f"shard {index}/{len(buckets)}: {summary} "
         f"[{elapsed:.0f}s] pid-exit={proc.returncode} log={log.name}")
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sharded pytest runner.")
    sub = parser.add_subparsers(dest="command")

    plan = sub.add_parser("plan", help="collect tests and write the shard plan")
    plan.add_argument("--shards", type=int, default=6)

    run = sub.add_parser("run", help="run one shard")
    run.add_argument("index", type=int)

    sub.add_parser("all", help="run every shard sequentially")
    sub.add_parser("summary", help="print the summary of the last 'all' run")

    if argv is None:
        argv = sys.argv[1:]
    extra: tuple[str, ...] = ()
    if "run" in argv or "all" in argv:
        # Everything after the subcommand that pytest itself understands
        # is forwarded verbatim (--durations=12, -x, -k ..., ...).
        for marker in ("run", "all"):
            if marker in argv:
                cut = argv.index(marker) + (2 if marker == "run" else 1)
                extra = tuple(argv[cut:])
                argv = argv[:cut]
                break

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "plan":
        if args.shards < 1:
            raise SystemExit(2)
        write_plan(args.shards)
        return 0

    if args.command == "run":
        buckets = load_plan()
        return run_shard(args.index, buckets, extra)

    if args.command == "summary":
        for line in (SHARD_DIR / "SUMMARY.txt").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            _out(line)
        return 0

    buckets = load_plan()
    started = time.time()
    failures = 0
    lines = []
    for i in range(1, len(buckets) + 1):
        code = run_shard(i, buckets, extra)
        if code != 0:
            failures += 1
        lines.append(
            f"shard {i}: exit={code} :: "
            f"{_result_line(SHARD_DIR / f'shard_{i}.log')}"
        )
    lines.append(f"shards={len(buckets)} failed_shards={failures} "
                 f"wall={time.time() - started:.0f}s")
    (SHARD_DIR / "SUMMARY.txt").write_text("\n".join(lines) + "\n",
                                           encoding="utf-8")
    for line in lines:
        _out(line)
    return 1 if failures else 0


if __name__ == "__main__":
    os.chdir(ROOT)
    raise SystemExit(main())
