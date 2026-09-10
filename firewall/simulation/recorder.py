"""Turn real authorization evaluations into replayable cases.

Recording is explicit and opt-in. Nothing in this module hooks, wraps,
patches, or otherwise interposes on ``authorize()`` -- a caller hands the
recorder a capability, a request, and the decision that was *already*
returned. That ordering matters: a recorder cannot influence a verdict it
only ever sees after the fact, so enabling recording can never change an
authorization outcome.

What gets captured is the material facts the gates reason about, read
through the SDK's own lineage resolver. Signatures and public keys are
never touched, so a case set is safe to write to disk and review.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

from firewall.capability import Capability
from firewall.simulation.case import (
    DEFAULT_LIFETIME_SECONDS,
    CaseSet,
    DelegationHop,
    RequestCase,
    SimulationError,
)

#: Retained cases. A recorder is a rolling window, not an archive; the
#: lifecycle log is the durable record.
RECORDER_LIMIT = 500


def _fingerprint_case(
    agents: tuple[str, ...],
    capability: str,
    action: str,
    request: dict[str, Any],
    constraints: dict[str, Any],
) -> str:
    """A stable id for one *shape* of request.

    Two evaluations of the same chain, action, and payload collapse to
    one case, so a busy workspace does not fill the window with
    duplicates of a single hot path.
    """

    material = json.dumps(
        {
            "agents": list(agents),
            "capability": capability,
            "action": action,
            "request": request,
            "constraints": constraints,
        },
        sort_keys=True,
        default=str,
    )

    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()

    return digest[:16]


class CaseRecorder:
    """A bounded, rolling window of replayable cases."""

    def __init__(
        self,
        *,
        limit: int = RECORDER_LIMIT,
    ):
        if isinstance(limit, bool) or not isinstance(
            limit,
            int,
        ):
            raise SimulationError(
                "limit must be an integer"
            )

        if limit <= 0:
            raise SimulationError(
                "limit must be positive"
            )

        self.limit = limit
        self._cases: dict[str, RequestCase] = {}

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        sdk: Any,
        capability: Capability,
        action: str,
        request: Optional[dict[str, Any]] = None,
        decision: Any = None,
        *,
        note: Optional[str] = None,
        now: Optional[float] = None,
    ) -> RequestCase:
        """Capture one already-evaluated request as a case."""

        if not isinstance(capability, Capability):
            raise SimulationError(
                "capability must be a Capability"
            )

        moment = (
            time.time() if now is None else now
        )
        payload = dict(request or {})

        chain = self._chain(sdk, capability)
        root = chain[0]
        leaf = chain[-1]

        hops = tuple(
            DelegationHop(
                delegatee=member.agent_id,
                constraints=dict(
                    member.constraints or {}
                ),
            )
            for member in chain[1:]
        )

        agents = tuple(
            member.agent_id for member in chain
        )

        remaining = (
            float(leaf.expires_at) - moment
        )
        expired = remaining <= 0

        allowed = getattr(
            decision,
            "allowed",
            None,
        )
        reason = getattr(
            decision,
            "reason",
            None,
        )

        case = RequestCase(
            case_id=_fingerprint_case(
                agents,
                leaf.capability,
                action,
                payload,
                dict(leaf.constraints or {}),
            ),
            action=action,
            capability=leaf.capability,
            root_agent=root.agent_id,
            issuer=root.issuer,
            root_constraints=dict(
                root.constraints or {}
            ),
            hops=hops,
            request=payload,
            tool=root.tool,
            lifetime=(
                DEFAULT_LIFETIME_SECONDS
                if expired
                else remaining
            ),
            revoked_agents=self._revoked(
                sdk,
                chain,
            ),
            expired=expired,
            baseline_allowed=(
                allowed
                if isinstance(allowed, bool)
                else None
            ),
            baseline_reason=(
                reason
                if isinstance(reason, str)
                else None
            ),
            recorded_at=moment,
            note=note,
        )

        self._cases[case.case_id] = case

        if len(self._cases) > self.limit:
            oldest = next(iter(self._cases))
            del self._cases[oldest]

        return case

    # ------------------------------------------------------------------
    # Chain resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _chain(
        sdk: Any,
        capability: Capability,
    ) -> tuple[Capability, ...]:
        """The delegation chain, root first.

        This calls the same lineage resolver the authoritative delegation
        gate uses, so a recorded case reflects the authority the pipeline
        actually resolved. A resolution failure degrades to a single-link
        chain rather than raising: recording must never be able to break
        the caller that is recording.
        """

        try:
            authority = (
                sdk._resolve_delegation_authority(
                    capability
                )
            )
            members = tuple(
                authority.capabilities
            )
        except Exception:
            members = ()

        if not members:
            return (capability,)

        # The resolver reports leaf-first; a case is built root-first.
        return tuple(reversed(members))

    @staticmethod
    def _revoked(
        sdk: Any,
        chain: tuple[Capability, ...],
    ) -> tuple[str, ...]:
        """Agents whose own capability was directly revoked.

        Only direct revocations are recorded. Transitive revocation is
        *derived* by the real revocation gate during replay, so recording
        it here would risk baking in a stale answer instead of letting
        the pipeline recompute one.
        """

        revoked = []

        for member in chain:
            try:
                if sdk.is_revoked(member):
                    revoked.append(
                        member.agent_id
                    )
            except Exception:
                continue

        return tuple(revoked)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def cases(self) -> CaseSet:
        return CaseSet(self._cases.values())

    def clear(self) -> None:
        self._cases.clear()

    def __len__(self) -> int:
        return len(self._cases)
