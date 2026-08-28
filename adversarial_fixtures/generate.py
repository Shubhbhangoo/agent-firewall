"""Generate the committed adversarial fixtures under adversarial_fixtures/.

Run with the project venv:

    .venv\\Scripts\\python adversarial_fixtures\\generate.py

Each fixture is a real .afw artifact produced by the recorder, then
deliberately damaged in exactly one documented way. The verifier's
expected status for each file is listed in FIXTURES.md and asserted by
test_v1_8_fixtures.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from firewall.artifact import artifact_to_json, write_artifact
from firewall.incident import redact_artifact
from firewall.recorder import (
    EventType,
    FlightRecorder,
    RecorderIdentity,
    compute_event_hash,
)
from firewall.verify import verify_artifact

HERE = Path(__file__).resolve().parent


def _clean_session() -> dict:
    recorder = FlightRecorder(
        session_id="fixture-session",
        agent="agent-fixture",
        checkpoint_every=3,
        clock=lambda: 1700000000.0,
    )
    recorder.start()
    recorder.record(
        EventType.AUTHORITY_ISSUED,
        {"capability": "payments.send", "issuer": "trusted-issuer"},
    )
    for index in range(4):
        recorder.record(
            EventType.AUTHORIZATION,
            {
                "action": "payments.send",
                "allowed": index % 2 == 0,
                "reason": "authorized"
                if index % 2 == 0
                else "constraint_denied",
                "amount": 20 if index % 2 == 0 else 9999,
            },
        )
    recorder.finalize()
    return recorder.artifact()


def _secret_session() -> dict:
    recorder = FlightRecorder(
        session_id="fixture-secret",
        agent="agent-fixture",
        checkpoint_every=3,
        clock=lambda: 1700000000.0,
    )
    recorder.record(
        EventType.TOOL_RESULT,
        {"tool": "db.read", "password": "hunter2"},
    )
    recorder.finalize()
    return recorder.artifact()


def main() -> None:
    artifacts: dict[str, dict] = {}

    artifacts["verified.afw"] = _clean_session()

    tampered = _clean_session()
    for event in tampered["events"]:
        # Flip a recorded DENIAL into an allow.
        if (
            event["type"] == "authorization"
            and event["payload"].get("allowed") is False
        ):
            event["payload"]["allowed"] = True
            event["payload"]["reason"] = "authorized"
            break
    artifacts["tampered-event.afw"] = tampered

    reordered = _clean_session()
    reordered["events"][1], reordered["events"][2] = (
        reordered["events"][2],
        reordered["events"][1],
    )
    artifacts["reordered-events.afw"] = reordered

    deleted = _clean_session()
    del deleted["events"][2]
    artifacts["deleted-event.afw"] = deleted

    badsig = _clean_session()
    badsig["checkpoints"][-1]["signature"] = (
        "A" * len(badsig["checkpoints"][-1]["signature"])
    )
    artifacts["bad-checkpoint-signature.afw"] = badsig

    wrong_identity = _clean_session()
    other = RecorderIdentity.generate()
    wrong_identity["recorder"]["public_key"] = other.public_b64
    wrong_identity["recorder"]["fingerprint"] = other.fingerprint
    artifacts["wrong-recorder-identity.afw"] = wrong_identity

    incomplete = _clean_session()
    incomplete["events"] = incomplete["events"][:-1]
    incomplete["session"]["ended_at"] = None
    incomplete["session"]["finalized"] = False
    incomplete["checkpoints"] = [
        checkpoint
        for checkpoint in incomplete["checkpoints"]
        if checkpoint["seq"] <= len(incomplete["events"])
    ]
    artifacts["incomplete-session.afw"] = incomplete

    artifacts["redacted-session.afw"] = redact_artifact(_secret_session())

    forged_tail = _clean_session()
    last = forged_tail["events"][-1]
    forged_tail["events"].append(
        {
            "seq": last["seq"] + 1,
            "type": "authority_revoked",
            "timestamp": last["timestamp"] + 1,
            "session": "fixture-session",
            "agent": "agent-fixture",
            "payload": {"capability": "payments.send", "reason": "forged"},
            "prev_hash": last["hash"],
            "hash": compute_event_hash(
                seq=last["seq"] + 1,
                type="authority_revoked",
                timestamp=last["timestamp"] + 1,
                session="fixture-session",
                agent="agent-fixture",
                payload={"capability": "payments.send", "reason": "forged"},
                prev_hash=last["hash"],
            ),
        }
    )
    artifacts["forged-tail-event.afw"] = forged_tail

    truncated_text = artifact_to_json(_clean_session())
    artifacts["truncated-json.afw"] = {
        "_text": truncated_text[: len(truncated_text) // 2]
    }

    # Deterministic formatting for committed fixtures.
    for name, artifact in artifacts.items():
        if "_text" in artifact:
            (HERE / name).write_text(
                artifact["_text"], encoding="utf-8"
            )
            continue

        write_artifact(artifact, HERE / name)

    # FIXTURES.md with expected statuses.
    expected = {
        "verified.afw": "verified",
        "tampered-event.afw": "failed",
        "reordered-events.afw": "failed",
        "deleted-event.afw": "failed",
        "bad-checkpoint-signature.afw": "failed",
        "wrong-recorder-identity.afw": "failed",
        "incomplete-session.afw": "incomplete",
        "redacted-session.afw": "redacted",
        "forged-tail-event.afw": "failed",
        "truncated-json.afw": "unverifiable",
    }

    lines = [
        "# Adversarial fixtures",
        "",
        "Each file is a real artifact produced by the v1.8 flight recorder,",
        "then deliberately damaged in exactly one documented way. The",
        "expected verification status is asserted by",
        "`test_v1_8_fixtures.py`.",
        "",
        "| fixture | damage | expected status |",
        "| --- | --- | --- |",
    ]

    for name in sorted(expected):
        lines.append(f"| {name} | {name} | {expected[name]} |")

    lines.append("")
    lines.append("Regenerate with: `.venv\\\\Scripts\\\\python adversarial_fixtures\\\\generate.py`")
    lines.append("")

    (HERE / "FIXTURES.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )

    # Cross-check every fixture now.
    for name, expected_status in expected.items():
        report = verify_artifact(
            (HERE / name).read_text(encoding="utf-8")
        )
        status = report.status
        if expected_status == "failed" and status == "failed":
            continue
        if status != expected_status:
            print(f"MISMATCH {name}: expected {expected_status}, got {status}")

    print(f"generated {len(expected)} fixtures in {HERE}")


if __name__ == "__main__":
    main()
