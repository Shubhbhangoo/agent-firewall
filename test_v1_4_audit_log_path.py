import os

from firewall.engine import Firewall


def make_policy(tmp_path):
    policy = tmp_path / "policy.yaml"

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


def test_audit_log_path_is_independent_of_cwd(tmp_path):
    policy = make_policy(tmp_path)

    first_cwd = tmp_path / "first"
    second_cwd = tmp_path / "second"

    first_cwd.mkdir()
    second_cwd.mkdir()

    original_cwd = os.getcwd()

    try:
        os.chdir(first_cwd)

        fw1 = Firewall(
            str(policy)
        )

        result = fw1.check(
            "agent-a",
            "payments.send",
            {"amount": 10},
        )

        assert result.action == "allow"

        audit_files_after_first = list(
            tmp_path.rglob("audit.log")
        )

        assert audit_files_after_first

        os.chdir(second_cwd)

        fw2 = Firewall(
            str(policy)
        )

        result2 = fw2.check(
            "agent-a",
            "payments.send",
            {"amount": 10},
        )

        assert result2.action == "allow"

        audit_files_after_second = list(
            tmp_path.rglob("audit.log")
        )

        # A CWD-independent implementation should keep using
        # the same audit log rather than creating another one.
        assert len(
            audit_files_after_second
        ) == 1

    finally:
        os.chdir(original_cwd)