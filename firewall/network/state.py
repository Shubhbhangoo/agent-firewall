"""Network state persistence (v1.9).

A network state file records which artifacts a :class:`CorrelationIndex`
has ingested (by path), so CLI commands can rebuild the graph,
detections, attack paths, and simulations without re-ingesting every
time. The state file holds paths and verification statuses only -- never
artifact content, and never secrets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.network.correlation import (
    CorrelationError,
    CorrelationIndex,
)

#: State file format marker.
STATE_FORMAT = "agent-firewall-network-state"
STATE_VERSION = 1


class NetworkStateError(ValueError):
    """Raised for a malformed network state file."""


def build_state(
    entries: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build a network state document from ingest records."""

    return {
        "format": STATE_FORMAT,
        "version": STATE_VERSION,
        "artifacts": [
            {
                "path": entry.get("path"),
                "artifact_id": entry.get("artifact_id"),
                "verification": entry.get("verification"),
                "agents": list(entry.get("agents", ())),
            }
            for entry in entries
        ],
    }


def save_state(
    state: dict[str, Any],
    path: str | Path,
) -> Path:
    """Write a network state file deterministically."""

    target = Path(path)

    if target.parent and str(target.parent) != ".":
        target.parent.mkdir(parents=True, exist_ok=True)

    target.write_text(
        json.dumps(
            state,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return target


def load_state(
    path: str | Path,
) -> dict[str, Any]:
    """Read and validate a network state file."""

    target = Path(path)

    try:
        payload = json.loads(
            target.read_text(encoding="utf-8")
        )
    except OSError as exc:
        raise NetworkStateError(
            f"cannot read {target}: {exc}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise NetworkStateError(
            "network state is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise NetworkStateError(
            "network state must be an object"
        )

    if payload.get("format") != STATE_FORMAT:
        raise NetworkStateError(
            "not an agent firewall network state file"
        )

    artifacts = payload.get("artifacts")

    if not isinstance(artifacts, list):
        raise NetworkStateError(
            "network state is missing 'artifacts'"
        )

    return payload


def build_index(
    state: dict[str, Any],
    *,
    allow_failed: bool = False,
) -> tuple[CorrelationIndex, dict[str, str]]:
    """Rebuild a CorrelationIndex from a state file.

    Returns ``(index, path_by_id)``. Artifacts that no longer exist on
    disk are skipped and reported via ``NetworkStateError`` when none of
    them can be loaded.
    """

    index = CorrelationIndex(allow_failed=allow_failed)
    path_by_id: dict[str, str] = {}

    loaded = 0

    for entry in state.get("artifacts", []):
        if not isinstance(entry, dict):
            continue

        path = entry.get("path")
        artifact_id = entry.get("artifact_id")

        if not isinstance(path, str) or not path:
            continue

        target = Path(path)

        if not target.exists():
            continue

        try:
            record = index.ingest_path(
                target,
                artifact_id=artifact_id,
            )
            path_by_id[record.artifact_id] = path
            loaded += 1
        except CorrelationError:
            continue

    if loaded == 0:
        raise NetworkStateError(
            "no artifacts from the state file could be loaded"
        )

    return index, path_by_id
