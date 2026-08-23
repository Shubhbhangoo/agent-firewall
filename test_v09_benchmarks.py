from __future__ import annotations

import statistics
import time

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.lifecycle_store import (
    SQLiteLifecycleStore,
)

from firewall.sdk import FirewallSDK

from firewall.tools import (
    ProtectedTool,
)

from firewall.adapters.generic import (
    GenericToolAdapter,
    GenericToolCall,
)

from firewall.adapters.openai import (
    OpenAITool,
)

from firewall.adapters.anthropic import (
    AnthropicTool,
)


# ============================================================
# Helpers
# ============================================================


def make_capability(
    sdk,
    capability="payments.send",
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability=capability,
    )


def benchmark(
    name,
    function,
    *,
    iterations=1000,
    warmup=100,
):
    for _ in range(warmup):
        function()

    samples = []

    for _ in range(iterations):
        start = time.perf_counter_ns()
        function()
        end = time.perf_counter_ns()

        samples.append(
            end - start
        )

    total_ms = (
        sum(samples)
        / 1_000_000
    )

    average_us = (
        statistics.mean(samples)
        / 1_000
    )

    median_us = (
        statistics.median(samples)
        / 1_000
    )

    p95_us = (
        sorted(samples)[
            int(
                len(samples) * 0.95
            )
            - 1
        ]
        / 1_000
    )

    print(
        f"{name:<35}"
        f" avg={average_us:>10.2f} us"
        f" median={median_us:>10.2f} us"
        f" p95={p95_us:>10.2f} us"
        f" total={total_ms:>10.2f} ms"
    )


# ============================================================
# Benchmarks
# ============================================================


def test_benchmark_capability_verification():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    benchmark(
        "Capability verification",
        lambda: sdk.verifier.verify(
            capability
        ),
        iterations=1000,
    )

    sdk.close()


def test_benchmark_authorization():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    benchmark(
        "SDK authorization",
        lambda: sdk.authorize(
            capability,
            "payments.send",
            {},
        ),
        iterations=500,
    )

    sdk.close()


def test_benchmark_protected_tool():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: 42,
    )

    benchmark(
        "ProtectedTool execution",
        lambda: tool(),
        iterations=500,
    )

    sdk.close()


def test_benchmark_generic_adapter():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    call = GenericToolCall(
        name="echo",
        arguments={
            "value": 42,
        },
    )

    benchmark(
        "Generic adapter execution",
        lambda: tool.execute(
            call
        ),
        iterations=500,
    )

    sdk.close()


def test_benchmark_openai_adapter():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    arguments = {
        "value": 42,
    }

    benchmark(
        "OpenAI adapter execution",
        lambda: tool.execute(
            arguments
        ),
        iterations=500,
    )

    sdk.close()


def test_benchmark_anthropic_adapter():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    call = {
        "name": "echo",
        "input": {
            "value": 42,
        },
    }

    benchmark(
        "Anthropic adapter execution",
        lambda: tool.execute(
            call
        ),
        iterations=500,
    )

    sdk.close()


def test_benchmark_lifecycle_persistence(
    tmp_path,
):
    path = (
        tmp_path
        / "lifecycle.db"
    )

    store = SQLiteLifecycleStore(
        path
    )

    capability = make_capability(
        FirewallSDK()
    )

    fingerprint = (
        capability.to_dict()
        .get("fingerprint", "benchmark")
    )

    # Use a stable identifier. The benchmark
    # measures persistence append latency,
    # not fingerprint generation.
    fingerprint = str(
        fingerprint
    )

    counter = [0]

    def append():
        counter[0] += 1

        store.append(
            __import__(
                "firewall.lifecycle",
                fromlist=[
                    "LifecycleEvent"
                ],
            ).LifecycleEvent(
                event_type=(
                    LifecycleEventType.USED
                ),
                fingerprint=(
                    f"{fingerprint}-{counter[0]}"
                ),
                timestamp=float(
                    counter[0]
                ),
                agent_id="agent-a",
                capability="payments.send",
                issuer="trusted-issuer",
                details={
                    "benchmark": True,
                },
            )
        )

    benchmark(
        "SQLite lifecycle append",
        append,
        iterations=100,
        warmup=10,
    )

    store.close()


def test_benchmark_lifecycle_read(
    tmp_path,
):
    path = (
        tmp_path
        / "lifecycle.db"
    )

    store = SQLiteLifecycleStore(
        path
    )

    from firewall.lifecycle import (
        LifecycleEvent,
    )

    for index in range(100):
        store.append(
            LifecycleEvent(
                event_type=(
                    LifecycleEventType.USED
                ),
                fingerprint=f"fp-{index}",
                timestamp=float(index),
                agent_id="agent-a",
                capability="payments.send",
                issuer="trusted-issuer",
                details={
                    "index": index,
                },
            )
        )

    benchmark(
        "SQLite lifecycle read",
        lambda: store.events(),
        iterations=100,
        warmup=10,
    )

    store.close()


def test_benchmark_report_is_generated():
    print()
    print("=" * 80)
    print("Agent Firewall v0.9 benchmark suite")
    print("=" * 80)
    print(
        "Run this file directly with pytest -s "
        "to display benchmark output."
    )
    print("=" * 80)

    assert True