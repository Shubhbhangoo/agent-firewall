import time

from firewall.engine import Firewall


def test_firewall_handles_many_requests(tmp_path, monkeypatch):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    fw = Firewall(str(policy_file))

    start = time.perf_counter()

    results = []

    for _ in range(1000):
        results.append(
            fw.check(
                "test-agent",
                "test.tool",
                {},
            )
        )

    elapsed = time.perf_counter() - start

    assert len(results) == 1000
    assert all(
        result.action == "allow"
        for result in results
    )

    print(f"\n1000 requests: {elapsed:.4f}s")

    assert elapsed < 5.0


def test_firewall_handles_mixed_requests(tmp_path, monkeypatch):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow

  - tool: dangerous.tool
    action: deny
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    fw = Firewall(str(policy_file))

    start = time.perf_counter()

    for index in range(1000):
        if index % 2 == 0:
            result = fw.check(
                "test-agent",
                "test.tool",
                {},
            )

            assert result.action == "allow"

        else:
            result = fw.check(
                "attacker-agent",
                "dangerous.tool",
                {},
            )

            assert result.action == "deny"

    elapsed = time.perf_counter() - start

    print(f"\n1000 mixed requests: {elapsed:.4f}s")

    assert elapsed < 5.0