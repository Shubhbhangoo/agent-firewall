from __future__ import annotations

import os

from firewall.engine import Firewall


def make_policy(tmp_path):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        """
rules:
  - tool: payments.send
    agent: agent-a
    action: allow
""",
        encoding="utf-8",
    )

    return policy


def test_audit_log_is_stable_across_working_directory_changes(
    tmp_path,
):
    policy = make_policy(tmp_path)

    original_cwd = os.getcwd()

    try:
        os.chdir(tmp_path)

        fw = Firewall(
            str(policy)
        )

        first = fw.check(
            "agent-a",
            "payments.send",
            {"amount": 10},
        )

        assert first.action == "allow"

        assert (
            tmp_path / "audit.log"
        ).exists()

        os.chdir(
            tmp_path.parent
        )

        second = Firewall(
            str(policy)
        )

        assert second.verify_audit_chain()

    finally:
        os.chdir(original_cwd)