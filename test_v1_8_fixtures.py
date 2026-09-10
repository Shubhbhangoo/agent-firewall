"""v1.8 fixture assertions: every committed adversarial fixture verifies
to exactly the documented status."""

from __future__ import annotations

from pathlib import Path

import pytest

from firewall.verify import verify_artifact

FIXTURES = Path(__file__).resolve().parent / "adversarial_fixtures"

EXPECTED = {
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


def test_fixture_files_exist():
    for name in EXPECTED:
        assert (FIXTURES / name).exists(), name


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_fixture_verifies_to_documented_status(name, expected):
    report = verify_artifact(
        (FIXTURES / name).read_text(encoding="utf-8")
    )
    assert report.status == expected, (
        f"{name}: expected {expected}, got {report.status}"
    )


def test_failed_fixtures_carry_actionable_findings():
    for name in (
        "tampered-event.afw",
        "reordered-events.afw",
        "deleted-event.afw",
        "bad-checkpoint-signature.afw",
        "forged-tail-event.afw",
    ):
        report = verify_artifact(
            (FIXTURES / name).read_text(encoding="utf-8")
        )
        assert report.status == "failed"
        errors = [
            finding
            for finding in report.findings
            if finding.severity == "error"
        ]
        assert errors, name
        assert all(
            finding.message for finding in errors
        ), name


def test_verified_fixture_has_no_error_findings():
    report = verify_artifact(
        (FIXTURES / "verified.afw").read_text(encoding="utf-8")
    )
    assert report.status == "verified"
    assert not [
        f for f in report.findings if f.severity == "error"
    ]
