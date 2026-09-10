"""Cross-artifact evidence correlation (v1.9).

A :class:`CorrelationIndex` ingests many artifacts, verifies each one,
extracts its network entities, and groups them into *correlation
bundles* so investigations can span multiple artifacts:

* shared correlation ids (recorded in artifact ``meta``),
* shared agents,
* shared sessions,
* declared incident membership,
* provenance relationships (redaction exports record the source hash).

The index never conflates integrity with trust: every artifact is run
through the independent verifier on ingest, and a failed artifact is
refused (or, with ``allow_failed=True``, ingested but flagged so
callers can exclude it). A correlation bundle records which artifacts
it contains, how they are related, and the verification status of each.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.artifact import ArtifactError, artifact_from_path
from firewall.network.graph import (
    AgentNetworkGraph,
    extract_network_entities,
)
from firewall.network.model import EntityType, Provenance
from firewall.verify import VerificationReport, verify_artifact

#: A correlation id key read from artifact meta.
CORRELATION_META_KEY = "correlation_id"

#: An incident id key read from artifact meta.
INCIDENT_META_KEY = "incident_id"


class CorrelationError(ValueError):
    """Raised for a malformed correlation request."""


@dataclass(frozen=True)
class IngestedArtifact:
    """One verified artifact known to the index."""

    artifact_id: str
    session_id: str
    verification: str
    findings: int
    agents: tuple[str, ...]
    correlation_ids: tuple[str, ...]
    incident_ids: tuple[str, ...]
    derived_from: Optional[str] = None
    verification_report: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "session_id": self.session_id,
            "verification": self.verification,
            "findings": self.findings,
            "agents": list(self.agents),
            "correlation_ids": list(self.correlation_ids),
            "incident_ids": list(self.incident_ids),
            "derived_from": self.derived_from,
        }


@dataclass(frozen=True)
class CorrelationBundle:
    """A group of artifacts related by shared identifiers."""

    bundle_id: str
    reason: str
    artifact_ids: tuple[str, ...]
    verification_statuses: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "reason": self.reason,
            "artifact_ids": list(self.artifact_ids),
            "verification_statuses": list(
                self.verification_statuses
            ),
        }


class CorrelationIndex:
    """Ingests, verifies, and correlates multiple artifacts."""

    def __init__(
        self,
        *,
        allow_failed: bool = False,
    ) -> None:
        self._artifacts: dict[str, dict[str, Any]] = {}
        self._records: dict[str, IngestedArtifact] = {}
        self._allow_failed = allow_failed

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        artifact: dict[str, Any],
        *,
        artifact_id: Optional[str] = None,
    ) -> IngestedArtifact:
        """Verify and index one artifact.

        Raises :class:`CorrelationError` for a failed/unverifiable
        artifact unless ``allow_failed=True`` was set, in which case the
        artifact is indexed but permanently flagged.
        """

        report = verify_artifact(artifact)

        if report.status in ("failed", "unverifiable"):
            if not self._allow_failed:
                raise CorrelationError(
                    f"refusing to ingest artifact: verification "
                    f"status is {report.status}"
                )

        if artifact_id is None:
            artifact_id = str(
                artifact.get("session", {}).get("id", "artifact")
            )

        session = artifact.get("session", {})
        meta = artifact.get("meta", {}) or {}

        agents = tuple(
            sorted(
                {
                    entry.get("agent") or "system"
                    for entry in artifact.get("events", [])
                    if isinstance(entry, dict)
                    and isinstance(entry.get("agent"), str)
                }
            )
        )

        correlation_ids = _meta_list(meta, CORRELATION_META_KEY)
        incident_ids = _meta_list(meta, INCIDENT_META_KEY)

        provenance = artifact.get("provenance", {}) or {}

        record = IngestedArtifact(
            artifact_id=artifact_id,
            session_id=str(session.get("id", "")),
            verification=report.status,
            findings=len(report.findings),
            agents=agents,
            correlation_ids=correlation_ids,
            incident_ids=incident_ids,
            derived_from=(
                provenance.get("derived_from")
                if isinstance(provenance, dict)
                else None
            ),
            verification_report=report.to_dict(),
        )

        self._artifacts[artifact_id] = dict(artifact)
        self._records[artifact_id] = record
        return record

    def ingest_path(
        self,
        path: str | Path,
        *,
        artifact_id: Optional[str] = None,
    ) -> IngestedArtifact:
        try:
            artifact = artifact_from_path(path)
        except ArtifactError as exc:
            raise CorrelationError(str(exc)) from exc

        return self.ingest(
            artifact,
            artifact_id=artifact_id,
        )

    def ingest_many(
        self,
        artifacts: Iterable[dict[str, Any]],
    ) -> list[IngestedArtifact]:
        return [
            self.ingest(artifact)
            for artifact in artifacts
        ]

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        return tuple(self._records)

    def record(self, artifact_id: str) -> Optional[IngestedArtifact]:
        return self._records.get(artifact_id)

    def artifact(self, artifact_id: str) -> Optional[dict[str, Any]]:
        return self._artifacts.get(artifact_id)

    def verified_ids(self) -> tuple[str, ...]:
        return tuple(
            artifact_id
            for artifact_id, record in self._records.items()
            if record.verification in ("verified", "redacted")
        )

    def status_of(self, artifact_id: str) -> Optional[str]:
        record = self._records.get(artifact_id)
        return record.verification if record else None

    # ------------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------------

    def graph(
        self,
        *,
        include_flagged: bool = False,
    ) -> AgentNetworkGraph:
        """A merged network over the indexed artifacts.

        By default only verified/redacted artifacts contribute; a
        failed artifact's facts never enter the network.
        """

        selected = []

        for artifact_id, artifact in self._artifacts.items():
            status = self.status_of(artifact_id)

            if status in ("verified", "redacted"):
                selected.append(artifact)
            elif include_flagged:
                selected.append(artifact)

        return AgentNetworkGraph.from_artifacts(
            selected,
            verify=False,
        )

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def bundles(
        self,
        *,
        include_flagged: bool = False,
    ) -> tuple[CorrelationBundle, ...]:
        """Group artifacts by shared correlation/incident ids, shared
        agents, and provenance relationships."""

        groups: dict[str, dict[str, Any]] = {}

        def add_group(
            key: str,
            reason: str,
            artifact_id: str,
        ) -> None:
            entry = groups.setdefault(
                key,
                {"reason": reason, "ids": []},
            )
            if artifact_id not in entry["ids"]:
                entry["ids"].append(artifact_id)

        records = list(self._records.items())

        if not include_flagged:
            records = [
                (aid, rec)
                for aid, rec in records
                if rec.verification in ("verified", "redacted")
            ]

        for artifact_id, record in records:
            for cid in record.correlation_ids:
                add_group(
                    f"correlation:{cid}",
                    "shared correlation id",
                    artifact_id,
                )
            for iid in record.incident_ids:
                add_group(
                    f"incident:{iid}",
                    "shared incident id",
                    artifact_id,
                )
            for agent in record.agents:
                add_group(
                    f"agent:{agent}",
                    "shared agent",
                    artifact_id,
                )
            if record.derived_from:
                add_group(
                    f"derived:{record.derived_from}",
                    "redaction derivation",
                    artifact_id,
                )

        bundles: list[CorrelationBundle] = []

        for key, entry in groups.items():
            ids = tuple(sorted(entry["ids"]))

            if len(ids) < 2:
                continue

            statuses = tuple(
                self.status_of(aid) for aid in ids
            )

            bundles.append(
                CorrelationBundle(
                    bundle_id=key,
                    reason=entry["reason"],
                    artifact_ids=ids,
                    verification_statuses=statuses,
                )
            )

        return tuple(
            sorted(
                bundles,
                key=lambda bundle: bundle.bundle_id,
            )
        )

    def related(
        self,
        artifact_id: str,
    ) -> tuple[str, ...]:
        """Artifact ids related to ``artifact_id`` via bundles."""

        related: set[str] = set()

        for bundle in self.bundles():
            if artifact_id in bundle.artifact_ids:
                related.update(bundle.artifact_ids)

        related.discard(artifact_id)
        return tuple(sorted(related))


def _meta_list(
    meta: dict[str, Any],
    key: str,
) -> tuple[str, ...]:
    value = meta.get(key)

    if isinstance(value, str) and value.strip():
        return (value.strip(),)

    if isinstance(value, (list, tuple)):
        return tuple(
            str(item).strip()
            for item in value
            if isinstance(item, str) and item.strip()
        )

    return ()
