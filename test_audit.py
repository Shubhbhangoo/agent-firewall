import json
import uuid

from firewall.engine import Firewall


def test_audit_entry_has_request_id(tmp_path):
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "allow"


def test_audit_request_ids_are_unique(tmp_path, monkeypatch):
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

    fw.check("agent-1", "test.tool", {})
    fw.check("agent-2", "test.tool", {})

    lines = (tmp_path / "audit.log").read_text(
        encoding="utf-8"
    ).splitlines()

    entries = [json.loads(line) for line in lines]

    ids = [entry["request_id"] for entry in entries]

    assert len(ids) == 2
    assert len(set(ids)) == 2

    for request_id in ids:
        uuid.UUID(request_id)
        