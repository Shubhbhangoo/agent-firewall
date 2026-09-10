"""Incident packages and redaction export (v1.8).

An incident package bundles everything needed to understand, verify, and
reproduce a security incident from one artifact: the artifact itself,
its verification report, the security timeline, the security trajectory,
the relationship graph, and an optional replay analysis. It is a single
JSON document that can be attached to a bug report, dropped into CI, or
shared with another developer.

Two safety properties are first-class:

**Redaction export.** :func:`redact_artifact` produces a *new,
self-consistent* artifact derived from the original: every event payload
is scanned for credential-shaped values, the removed values are replaced
with a placeholder *before* re-hashing, the chain is re-linked, and the
checkpoints are re-signed by a fresh export identity. The derived
artifact verifies as ``redacted`` and declares its provenance (the hash
of the artifact it was derived from). The original bytes are never
mutated, and the private signing key is never needed.

**Never conflate evidence.** The package carries the verification report
verbatim, including ``failed`` and ``unverifiable`` statuses. A package
around a broken artifact says so.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.artifact import (
    ArtifactError,
    artifact_from_path,
    validate_manifest,
)
from firewall.recorder import (
    EventType,
    RecorderIdentity,
    SecurityEvent,
    canonical_bytes,
    compute_event_hash,
    redact_payload,
    sha256_hex,
    sign_checkpoint,
)
from firewall.replaylab import Laboratory
from firewall.simulation import MAX_CASES
from firewall.timeline import (
    SecurityGraph,
    build_timeline,
    trajectory_from_artifact,
)
from firewall.verify import verify_artifact

#: Incident package format marker.
INCIDENT_MAGIC = "agent-firewall-incident-package"
INCIDENT_VERSION = 1

#: Everything an incident package includes by default.
DEFAULT_INCLUDE = (
    "timeline",
    "trajectory",
    "graph",
    "replay",
)


class IncidentError(ValueError):
    """Raised for a malformed incident package request."""


# ----------------------------------------------------------------------
# Redaction export
# ----------------------------------------------------------------------


def redact_artifact(
    artifact: dict[str, Any],
) -> dict[str, Any]:
    """Return a redacted, self-consistent derivation of ``artifact``.

    The derived artifact has the same session, events (with
    credential-shaped payload values replaced), and checkpoint cadence,
    but a freshly recomputed hash chain and freshly signed checkpoints
    under a new export identity. Its ``provenance`` records the hash of
    the source artifact. Verifying the result reports ``redacted``.
    """

    validate_manifest(artifact)

    identity = RecorderIdentity.generate()
    source_hash = sha256_hex(
        canonical_bytes(artifact)
    )

    events: list[dict[str, Any]] = []
    redactions: list[dict[str, Any]] = []
    prev_hash = "0" * 64

    for index, entry in enumerate(
        artifact.get("events", []), start=1
    ):
        try:
            event = SecurityEvent.from_dict(entry)
        except Exception as exc:
            raise IncidentError(
                f"cannot redact malformed event {index}: {exc}"
            ) from exc

        redacted, found = redact_payload(
            event.payload
        )

        for item in found:
            redactions.append(
                {"seq": index, **item}
            )

        event_hash = compute_event_hash(
            seq=event.seq,
            type=event.type.value,
            timestamp=event.timestamp,
            session=event.session,
            agent=event.agent,
            payload=redacted,
            prev_hash=prev_hash,
        )

        events.append(
            {
                "seq": event.seq,
                "type": event.type.value,
                "timestamp": event.timestamp,
                "session": event.session,
                "agent": event.agent,
                "payload": redacted,
                "prev_hash": prev_hash,
                "hash": event_hash,
            }
        )

        prev_hash = event_hash

    checkpoints: list[dict[str, Any]] = []
    original_seqs = sorted(
        {
            checkpoint.get("seq")
            for checkpoint in artifact.get(
                "checkpoints", []
            )
            if isinstance(checkpoint, dict)
            and isinstance(checkpoint.get("seq"), int)
        }
    )

    for seq in original_seqs:
        if seq < 1 or seq > len(events):
            continue

        checkpoint = sign_checkpoint(
            identity,
            seq=seq,
            event_hash=events[seq - 1]["hash"],
            event_count=seq,
        )

        checkpoints.append(
            checkpoint.to_dict()
        )

    derived = dict(artifact)

    derived["events"] = events
    derived["checkpoints"] = checkpoints
    derived["recorder"] = {
        "algorithm": "Ed25519",
        "public_key": identity.public_b64,
        "fingerprint": identity.fingerprint,
    }
    derived["redactions"] = (
        list(artifact.get("redactions", []))
        + redactions
    )
    derived["provenance"] = {
        "derived_from": source_hash,
        "derived_by": "redaction-export",
    }

    meta = dict(artifact.get("meta", {}) or {})
    meta["redaction_export"] = True
    derived["meta"] = meta

    return derived


# ----------------------------------------------------------------------
# Incident package
# ----------------------------------------------------------------------


def create_incident_package(
    artifact: dict[str, Any],
    *,
    title: str,
    summary: str = "",
    include: Iterable[str] = DEFAULT_INCLUDE,
    redact: bool = False,
    replay_limit: int = MAX_CASES,
) -> dict[str, Any]:
    """Build an incident package around an artifact."""

    if not isinstance(title, str) or not title.strip():
        raise IncidentError(
            "title is required"
        )

    if not isinstance(summary, str):
        raise IncidentError(
            "summary must be a string"
        )

    if not isinstance(redact, bool):
        raise IncidentError(
            "redact must be a boolean"
        )

    base = (
        redact_artifact(artifact)
        if redact
        else validate_manifest(artifact)
    )

    included = set(include)

    package: dict[str, Any] = {
        "incident": INCIDENT_VERSION,
        "format": INCIDENT_MAGIC,
        "title": title,
        "summary": summary,
        "created_at": time.time(),
        "artifact": base,
        "verification": verify_artifact(base).to_dict(),
    }

    if "timeline" in included:
        package["timeline"] = [
            entry.to_dict()
            for entry in build_timeline(base)
        ]

    if "trajectory" in included:
        package["trajectory"] = (
            trajectory_from_artifact(base).to_dict()
        )

    if "graph" in included:
        package["graph"] = (
            SecurityGraph.from_artifact(base).to_dict()
        )

    if "replay" in included:
        try:
            laboratory = Laboratory(base)
            package["replay"] = laboratory.replay(
                limit=replay_limit
            ).to_dict()
        except Exception as exc:
            package["replay"] = {
                "error": f"{type(exc).__name__}: {exc}"
            }

    return package


def write_incident_package(
    package: dict[str, Any],
    path: str | Path,
) -> Path:
    """Write an incident package deterministically."""

    target = Path(path)

    if target.parent and str(target.parent) != ".":
        target.parent.mkdir(parents=True, exist_ok=True)

    target.write_text(
        json.dumps(
            package,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return target


def read_incident_package(
    path: str | Path,
) -> dict[str, Any]:
    """Read and validate an incident package."""

    target = Path(path)

    try:
        payload = json.loads(
            target.read_text(encoding="utf-8")
        )
    except OSError as exc:
        raise IncidentError(
            f"cannot read {target}: {exc}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise IncidentError(
            "incident package is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise IncidentError(
            "incident package must be an object"
        )

    if payload.get("incident") != INCIDENT_VERSION:
        raise IncidentError(
            "not an agent firewall incident package"
        )

    if not isinstance(
        payload.get("artifact"), dict
    ):
        raise IncidentError(
            "incident package carries no artifact"
        )

    return payload
