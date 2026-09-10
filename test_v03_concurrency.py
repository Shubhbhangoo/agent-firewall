from concurrent.futures import ThreadPoolExecutor

from firewall.engine import Firewall


def test_concurrent_requests_keep_decisions_correct(tmp_path, monkeypatch):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow

  - tool: payments.send
    amount_gte: 1000
    action: deny
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    fw = Firewall(str(policy_file))

    def make_request(index):
        if index % 2 == 0:
            return fw.check(
                f"agent-{index}",
                "test.tool",
                {},
            )

        return fw.check(
            f"agent-{index}",
            "payments.send",
            {"amount": 2000},
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(
            executor.map(make_request, range(50))
        )

    for index, result in enumerate(results):
        if index % 2 == 0:
            assert result.action == "allow"
        else:
            assert result.action == "deny"


def test_concurrent_audit_entries_are_valid_json(
    tmp_path,
    monkeypatch,
):
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

    def make_request(index):
        return fw.check(
            f"agent-{index}",
            "test.tool",
            {},
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(
            executor.map(make_request, range(50))
        )

    audit_file = tmp_path / "audit.log"

    lines = audit_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 50

    import json

    entries = [
        json.loads(line)
        for line in lines
    ]

    assert len(entries) == 50

    request_ids = [
        entry["request_id"]
        for entry in entries
    ]

    assert len(set(request_ids)) == 50