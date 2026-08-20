import json
import multiprocessing

from firewall.engine import Firewall


def worker(policy_file, workdir, index):
    import os

    os.chdir(workdir)

    fw = Firewall(policy_file)

    fw.check(
        f"process-agent-{index}",
        "test.tool",
        {},
    )


def test_concurrent_process_audit_logging(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    processes = []

    for index in range(20):
        process = multiprocessing.Process(
            target=worker,
            args=(
                str(policy_file),
                str(tmp_path),
                index,
            ),
        )

        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    assert all(
        process.exitcode == 0
        for process in processes
    )

    audit_file = tmp_path / "audit.log"

    lines = audit_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 20

    entries = [
        json.loads(line)
        for line in lines
    ]

    assert len(entries) == 20

    request_ids = [
        entry["request_id"]
        for entry in entries
    ]

    assert len(set(request_ids)) == 20