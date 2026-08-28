"""Deterministic writing of ``.afw`` artifacts.

``write_artifact`` serializes a validated artifact with sorted keys at
every level, so the same history always produces the same bytes. The
on-disk formatting is cosmetic (verification hashes the *parsed*
document), but deterministic output makes artifacts reviewable in git
and cacheable in CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from firewall.artifact.reader import (
    ArtifactError,
    validate_manifest,
)
from firewall.recorder.encoding import (
    canonical_bytes,
    validate_artifact_value,
)

#: Pretty-print indent used on disk.
INDENT = 2


def artifact_to_json(
    artifact: dict[str, Any],
    *,
    indent: int = INDENT,
) -> str:
    """Deterministic JSON text for a validated artifact."""

    data = validate_manifest(artifact)

    # Canonical validation first: reject anything (e.g. non-finite
    # numbers smuggled in after recording) that would make the artifact
    # unverifiable, before it is written.
    validate_artifact_value(data)

    return json.dumps(
        data,
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
    )


def artifact_to_bytes(
    artifact: dict[str, Any],
) -> bytes:
    """Compact canonical bytes for a validated artifact."""

    data = validate_manifest(artifact)
    validate_artifact_value(data)
    return canonical_bytes(data)


def write_artifact(
    artifact: dict[str, Any],
    path: str | Path,
) -> Path:
    """Write a validated artifact to ``path`` deterministically."""

    target = Path(path)

    if target.parent and str(target.parent) != ".":
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ArtifactError(
                f"cannot create {target.parent}: {exc}"
            ) from exc

    text = artifact_to_json(artifact) + "\n"

    try:
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ArtifactError(
            f"cannot write {target}: {exc}"
        ) from exc

    return target
