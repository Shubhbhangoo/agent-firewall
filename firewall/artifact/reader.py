"""Reading and structural validation of ``.afw`` artifacts.

Reading is deliberately shallow: it parses JSON and checks the top-level
shape (magic, version, session, recorder, events, checkpoints,
redactions). *Trust* is never inferred here -- the deep integrity and
signature checks live in :mod:`firewall.verify`, which treats everything
this module accepts as hostile input to be proven, not believed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Optional

from firewall.recorder.checkpoint import Checkpoint
from firewall.recorder.events import SecurityEvent

#: Format magic and version, fixed for the v1.8 format family.
ARTIFACT_MAGIC = "agent-firewall-security-artifact"
ARTIFACT_VERSION = 1

#: Hard ceiling on events accepted from a file, so a hostile or corrupt
#: artifact cannot force unbounded parsing.
MAX_EVENTS = 1_000_000

#: Hard ceiling on checkpoints.
MAX_CHECKPOINTS = 100_000


class ArtifactError(ValueError):
    """Raised when an artifact cannot be read."""


def _require_mapping(
    payload: Any,
    label: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ArtifactError(
            f"{label} must be an object"
        )
    return payload


def _require_list(
    payload: Any,
    label: str,
) -> list[Any]:
    if not isinstance(payload, list):
        raise ArtifactError(
            f"{label} must be a list"
        )
    return payload


def validate_manifest(
    artifact: Any,
) -> dict[str, Any]:
    """Validate the structural envelope of an artifact.

    Returns the artifact dict. Raises :class:`ArtifactError` for
    anything that is not recognizably an artifact at all; verifier-grade
    checks are deliberately left to :mod:`firewall.verify`.
    """

    data = _require_mapping(artifact, "artifact")

    if data.get("afw") != 1:
        raise ArtifactError(
            "not an agent firewall security artifact "
            "(missing afw=1)"
        )

    if data.get("format") != ARTIFACT_MAGIC:
        raise ArtifactError(
            f"unknown artifact format: {data.get('format')!r}"
        )

    version = data.get("format_version")

    if isinstance(version, bool) or not isinstance(
        version, int
    ):
        raise ArtifactError(
            "format_version must be an integer"
        )

    if version != ARTIFACT_VERSION:
        raise ArtifactError(
            f"unsupported artifact version: {version} "
            f"(this build reads version {ARTIFACT_VERSION})"
        )

    session = _require_mapping(
        data.get("session"),
        "session",
    )

    if not isinstance(session.get("id"), str) or not session["id"]:
        raise ArtifactError(
            "session.id must be a non-empty string"
        )

    recorder = _require_mapping(
        data.get("recorder"),
        "recorder",
    )

    if not isinstance(
        recorder.get("public_key"), str
    ) or not recorder["public_key"].strip():
        raise ArtifactError(
            "recorder.public_key must be a non-empty string"
        )

    events = _require_list(
        data.get("events"),
        "events",
    )

    if len(events) > MAX_EVENTS:
        raise ArtifactError(
            f"artifact has too many events (>{MAX_EVENTS})"
        )

    checkpoints = _require_list(
        data.get("checkpoints"),
        "checkpoints",
    )

    if len(checkpoints) > MAX_CHECKPOINTS:
        raise ArtifactError(
            f"artifact has too many checkpoints "
            f"(>{MAX_CHECKPOINTS})"
        )

    redactions = data.get("redactions", [])

    if redactions is not None:
        _require_list(redactions, "redactions")

    meta = data.get("meta", {})

    if meta is not None:
        _require_mapping(meta, "meta")

    return data


def artifact_from_json(text: str) -> dict[str, Any]:
    """Parse artifact JSON text and validate its envelope."""

    if not isinstance(text, str):
        raise ArtifactError(
            "artifact JSON must be a string"
        )

    try:
        payload = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ArtifactError(
            "artifact is not valid JSON"
        ) from exc

    return validate_manifest(payload)


def artifact_from_bytes(data: bytes) -> dict[str, Any]:
    """Parse artifact bytes (UTF-8 JSON) and validate."""

    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError(
            "artifact bytes required"
        )

    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactError(
            "artifact is not valid UTF-8"
        ) from exc

    return artifact_from_json(text)


def artifact_from_path(path: str | Path) -> dict[str, Any]:
    """Read and validate an artifact file."""

    target = Path(path)

    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ArtifactError(
            f"cannot read {target}: {exc}"
        ) from exc

    return artifact_from_json(text)


def artifact_from_file(file) -> dict[str, Any]:
    """Read and validate an artifact from an open file object."""

    return artifact_from_json(file.read())


def iter_events(
    artifact: dict[str, Any],
) -> Iterator[SecurityEvent]:
    """Yield validated ``SecurityEvent`` values in chain order.

    Raises :class:`ArtifactError` if an event is malformed.
    """

    for entry in validate_manifest(artifact)["events"]:
        yield SecurityEvent.from_dict(entry)


def iter_checkpoints(
    artifact: dict[str, Any],
) -> Iterator[Checkpoint]:
    """Yield validated ``Checkpoint`` values in order."""

    for entry in validate_manifest(artifact)["checkpoints"]:
        yield Checkpoint.from_dict(entry)


def event_count(artifact: dict[str, Any]) -> int:
    """Number of events in a validated artifact."""

    return len(
        validate_manifest(artifact)["events"]
    )


def session_summary(
    artifact: dict[str, Any],
) -> dict[str, Any]:
    """A safe, read-only summary of the artifact's session envelope."""

    data = validate_manifest(artifact)

    session = dict(data["session"])
    recorder = dict(data["recorder"])

    return {
        "session": session,
        "recorder": {
            "algorithm": recorder.get("algorithm"),
            "fingerprint": recorder.get("fingerprint"),
            "public_key": recorder.get("public_key"),
        },
        "generator": dict(data.get("generator", {})),
        "event_count": len(data["events"]),
        "checkpoint_count": len(data["checkpoints"]),
        "redaction_count": len(data.get("redactions", [])),
        "finalized": bool(session.get("finalized")),
    }
