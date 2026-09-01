"""Read-only projection of Agent Firewall state for the developer console.

This module is **presentation infrastructure only**. It contains no
authorization logic and it never makes, alters, or second-guesses a
security decision.

Three rules govern everything here:

1. **No decisions.** The only way this module obtains a decision is by
   calling the established ``FirewallSDK`` authorization API and
   reporting the result verbatim. There is no second authorization
   system, and no check is re-implemented.

2. **No secret material.** :class:`~firewall.capability.Capability`
   carries ``signature`` and ``public_key``, and the canonical
   ``SecurityDecision`` explicitly must not carry signatures or keys.
   Every projection here omits them and reports the withheld field
   names in ``redacted`` so the console can be honest about what it is
   not showing.

3. **No drift.** The pipeline shown to the user is derived from the
   SDK's real gate tuple, not from a hardcoded list. If a gate is
   added, removed, or reordered in the SDK, the console follows
   automatically rather than displaying a stale diagram.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.capability import Capability
from firewall.north_star import DelegationAuthority
from firewall.sdk import FirewallSDK


# ======================================================================
# Redaction
# ======================================================================

#: Capability fields that must never reach the console. ``signature``
#: and ``public_key`` are cryptographic material; the canonical
#: SecurityDecision contract forbids exposing them.
REDACTED_CAPABILITY_FIELDS = (
    "signature",
    "public_key",
)

#: Number of leading hex characters shown for a fingerprint. The full
#: fingerprint is a public identifier, not a secret, but truncating it
#: keeps the console readable.
FINGERPRINT_PREFIX = 12


def short_fingerprint(
    fingerprint: Optional[str],
) -> Optional[str]:
    """Return a display-length fingerprint prefix."""

    if not isinstance(fingerprint, str):
        return None

    if len(fingerprint) <= FINGERPRINT_PREFIX:
        return fingerprint

    return fingerprint[:FINGERPRINT_PREFIX]


# ======================================================================
# Pipeline projection
# ======================================================================

#: Human-facing labels for the SDK's real authorization gates. Keys are
#: the gate method names found in ``_authorization_gate_phases()``. A
#: gate with no entry here still renders (see ``_derive_label``), so the
#: console degrades gracefully instead of hiding an unknown gate.
GATE_LABELS: dict[str, dict[str, str]] = {
    "_gate_refusal": {
        "label": "Refusal",
        "summary": "Memoized prior denials short-circuit before any other work.",
    },
    "_gate_risk": {
        "label": "Risk",
        "summary": "Runtime agent risk state; escalates upward and never decays.",
    },
    "_gate_issuer": {
        "label": "Issuer",
        "summary": "Issuer must be currently trusted.",
    },
    "_gate_revocation": {
        "label": "Revocation",
        "summary": "Direct and transitive (ancestor) revocation.",
    },
    "_gate_time": {
        "label": "Time",
        "summary": "Validity window: not-yet-valid and expired.",
    },
    "_gate_delegation_chain": {
        "label": "Delegation",
        "summary": "Resolves lineage into an immutable DelegationAuthority.",
    },
    "_gate_delegation_monotonicity": {
        "label": "Delegation Monotonicity",
        "summary": "Every child in the chain must be narrower than or "
        "equal to its parent; a delegate cannot widen.",
    },
    "_gate_delegation_depth": {
        "label": "Depth Policy",
        "summary": "Optional ceiling on effective delegation depth.",
    },
    "_gate_cryptographic_authority": {
        "label": "Cryptographic Authority",
        "summary": "Signature verification plus constraints, for the "
        "capability and every ancestor.",
    },
    "_gate_transaction": {
        "label": "Security Transaction",
        "summary": "Semantic chain, security budget, and lifecycle "
        "commit as one atomic step.",
    },
}


def _derive_label(gate_id: str) -> str:
    """Best-effort label for a gate with no curated entry."""

    return (
        gate_id.removeprefix("_gate_")
        .replace("_", " ")
        .title()
    )


def pipeline_phases(
    sdk: FirewallSDK,
) -> list[dict[str, Any]]:
    """Project the SDK's real gate order into console nodes.

    The gate sequence is read from ``_authorization_gate_phases()`` --
    the same tuple ``authorize()`` iterates -- so the rendered pipeline
    cannot drift from the implementation. ``Request`` and ``Decision``
    terminals are added around the gates to frame the flow.
    """

    nodes: list[dict[str, Any]] = [
        {
            "id": "request",
            "label": "Request",
            "summary": "Capability, action, and request payload enter "
            "the pipeline.",
            "kind": "terminal",
        }
    ]

    for gate in sdk._authorization_gate_phases():
        gate_id = getattr(
            gate,
            "__name__",
            str(gate),
        )
        meta = GATE_LABELS.get(gate_id)

        nodes.append(
            {
                "id": gate_id,
                "label": (
                    meta["label"]
                    if meta
                    else _derive_label(gate_id)
                ),
                "summary": (
                    meta["summary"] if meta else ""
                ),
                "kind": "gate",
            }
        )

    nodes.append(
        {
            "id": "decision",
            "label": "Decision",
            "summary": "Canonical SecurityDecision returned to the caller.",
            "kind": "terminal",
        }
    )

    for index, node in enumerate(nodes):
        node["index"] = index

    return nodes


# ======================================================================
# Reason attribution
# ======================================================================

#: Exact denial reasons mapped to the gate that produces them. Derived
#: by reading the gate implementations; anything absent is reported as
#: unattributed rather than guessed.
REASON_TO_GATE: dict[str, str] = {
    # Pre-gate guard in authorize().
    "invalid_capability": "request",
    # _gate_refusal
    "refusal_state": "_gate_refusal",
    "invalid_refusal_scope": "_gate_refusal",
    # _gate_risk
    "risk_state_revoked": "_gate_risk",
    # _gate_issuer
    "untrusted_issuer": "_gate_issuer",
    # _gate_revocation
    "capability_revoked": "_gate_revocation",
    # _gate_time
    "expired": "_gate_time",
    "not_yet_valid": "_gate_time",
    # _gate_delegation_depth
    "delegation_depth_exceeded": "_gate_delegation_depth",
    # _gate_cryptographic_authority (authorization engine + policy)
    "invalid_signature": "_gate_cryptographic_authority",
    "verification_error": "_gate_cryptographic_authority",
    "constraint_denied": "_gate_cryptographic_authority",
    "policy_denied": "_gate_cryptographic_authority",
    "namespace_denied": "_gate_cryptographic_authority",
    "tool_binding_denied": "_gate_cryptographic_authority",
    "invalid_action": "_gate_cryptographic_authority",
    "invalid_request": "_gate_cryptographic_authority",
    "invalid_clock": "_gate_cryptographic_authority",
    "replay": "_gate_cryptographic_authority",
    # _gate_transaction
    "semantic_chain_denied": "_gate_transaction",
    "security_context_agent_mismatch": "_gate_transaction",
    "action budget exceeded": "_gate_transaction",
    "total amount budget exceeded": "_gate_transaction",
}

#: Reason prefixes for gates that embed an underlying error message.
REASON_PREFIX_TO_GATE: tuple[tuple[str, str], ...] = (
    (
        "delegation_chain_error:",
        "_gate_delegation_chain",
    ),
    (
        # The gate appends the failing monotonicity reason, so this is a
        # prefix rather than an exact reason.
        "delegation_widening:",
        "_gate_delegation_monotonicity",
    ),
    (
        "semantic_context_error:",
        "_gate_transaction",
    ),
    (
        "security_context_error:",
        "_gate_transaction",
    ),
)


def attribute_reason(
    reason: Optional[str],
) -> Optional[str]:
    """Return the gate id a denial reason originates from.

    Returns ``None`` when the reason is not recognized. The console
    renders that as *unattributed* -- an unknown reason must never be
    presented as though its origin were known.
    """

    if not isinstance(reason, str):
        return None

    if reason in REASON_TO_GATE:
        return REASON_TO_GATE[reason]

    for prefix, gate_id in REASON_PREFIX_TO_GATE:
        if reason.startswith(prefix):
            return gate_id

    if "budget exceeded" in reason:
        return "_gate_transaction"

    return None


def phase_trace(
    sdk: FirewallSDK,
    *,
    allowed: bool,
    reason: Optional[str],
) -> list[dict[str, Any]]:
    """Annotate each pipeline node with its status for one decision.

    Status is *derived* from the authoritative decision reason, not from
    instrumenting the gates. An allowed decision means every gate was
    passed. A denial marks the attributed gate ``denied``, everything
    before it ``passed``, and everything after it ``not_reached``.

    When a reason cannot be attributed, no gate is blamed: gates are
    reported ``unknown`` so the console never invents a stop point.
    """

    nodes = pipeline_phases(sdk)

    if allowed:
        for node in nodes:
            node["status"] = "passed"
        return nodes

    stop_at = attribute_reason(reason)

    if stop_at is None:
        for node in nodes:
            node["status"] = (
                "passed"
                if node["id"] == "request"
                else "unknown"
            )
        nodes[-1]["status"] = "denied"
        return nodes

    seen_stop = False

    for node in nodes:
        if node["id"] == stop_at:
            node["status"] = "denied"
            seen_stop = True
        elif seen_stop:
            node["status"] = "not_reached"
        else:
            node["status"] = "passed"

    # The decision terminal always reflects the outcome.
    nodes[-1]["status"] = "denied"

    return nodes


# ======================================================================
# Capability projection
# ======================================================================


def capability_view(
    sdk: FirewallSDK,
    capability: Capability,
    *,
    label: Optional[str] = None,
) -> dict[str, Any]:
    """Project a capability, withholding all cryptographic material."""

    fingerprint = sdk.fingerprint(capability)

    return {
        "label": label,
        "fingerprint": fingerprint,
        "fingerprint_short": short_fingerprint(
            fingerprint
        ),
        "agent_id": capability.agent_id,
        "capability": capability.capability,
        "issuer": capability.issuer,
        "issued_at": capability.issued_at,
        "expires_at": capability.expires_at,
        "tool": capability.tool,
        "key_id": capability.key_id,
        "constraints": dict(
            capability.constraints or {}
        ),
        "revoked": sdk.is_revoked(capability),
        "effectively_revoked": (
            sdk.is_effectively_revoked(
                capability
            )
        ),
        "redacted": list(
            REDACTED_CAPABILITY_FIELDS
        ),
    }


# ======================================================================
# Delegation authority projection
# ======================================================================


def authority_view(
    sdk: FirewallSDK,
    capability: Capability,
) -> dict[str, Any]:
    """Project the canonical DelegationAuthority for a capability.

    This calls the SDK's own lineage resolver, so the console shows the
    same effective authority the authoritative delegation gate uses. A
    resolution failure is reported as an error rather than hidden, and
    never as an authorization outcome.
    """

    try:
        authority = (
            sdk._resolve_delegation_authority(
                capability
            )
        )
    except Exception as exc:
        return {
            "resolved": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "depth": None,
            "max_depth": sdk.max_delegation_depth,
            "links": [],
        }

    if not isinstance(
        authority,
        DelegationAuthority,
    ):
        return {
            "resolved": False,
            "error_type": "TypeError",
            "error": "unexpected authority type",
            "depth": None,
            "max_depth": sdk.max_delegation_depth,
            "links": [],
        }

    links: list[dict[str, Any]] = []
    last = authority.depth - 1

    for position, member in enumerate(
        authority.capabilities
    ):
        if position == 0:
            role = "requested"
        elif position == last:
            role = "root"
        else:
            role = "ancestor"

        entry = capability_view(
            sdk,
            member,
        )
        entry["role"] = role
        entry["position"] = position
        links.append(entry)

    return {
        "resolved": True,
        "depth": authority.depth,
        "max_depth": sdk.max_delegation_depth,
        "requested_agent": authority.requested.agent_id,
        "root_agent": authority.root.agent_id,
        "fingerprints": [
            short_fingerprint(value)
            for value in authority.fingerprints
        ],
        "links": links,
    }


# ======================================================================
# Decision projection
# ======================================================================


def decision_view(
    decision: Any,
) -> dict[str, Any]:
    """Project a canonical SecurityDecision verbatim.

    Nothing is recomputed. ``allowed`` and ``reason`` are exactly what
    the SDK returned.
    """

    metadata = getattr(
        decision,
        "metadata",
        None,
    )

    return {
        "allowed": bool(decision.allowed),
        "reason": decision.reason,
        "capability_id": short_fingerprint(
            getattr(
                decision,
                "capability_id",
                None,
            )
        ),
        "agent": getattr(
            decision,
            "agent",
            None,
        ),
        "action": getattr(
            decision,
            "action",
            None,
        ),
        "tool": getattr(
            decision,
            "tool",
            None,
        ),
        "metadata": (
            dict(metadata) if metadata else None
        ),
    }


# ======================================================================
# Lifecycle / evidence projection
# ======================================================================


def lifecycle_view(
    sdk: FirewallSDK,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Project recent lifecycle events, newest first.

    Event details can contain the caller's request payload, which is
    application data rather than security material; it is preserved so
    the console can show real evidence. Capability fingerprints are
    truncated for display.
    """

    events = list(sdk.lifecycle_events())
    events.reverse()

    projected: list[dict[str, Any]] = []

    for event in events[:limit]:
        record = event.to_dict()
        record["fingerprint_short"] = (
            short_fingerprint(
                record.get("fingerprint")
            )
        )
        projected.append(record)

    return projected


def lifecycle_totals(
    sdk: FirewallSDK,
) -> dict[str, int]:
    """Count lifecycle events by type."""

    totals: dict[str, int] = {}

    for event in sdk.lifecycle_events():
        key = event.event_type.value
        totals[key] = totals.get(key, 0) + 1

    return totals


# ======================================================================
# Posture projection
# ======================================================================


def posture_view(
    sdk: FirewallSDK,
    *,
    agents: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Project risk, refusal, and configured policy posture."""

    risk = sdk.get_risk_context()
    refusal = sdk.get_refusal_state()
    security = sdk.get_security_context()
    semantic = sdk.get_semantic_context()

    risk_rows: list[dict[str, Any]] = []

    if risk is not None:
        for agent in agents:
            try:
                snapshot = risk.snapshot(agent)
            except Exception:
                continue

            risk_rows.append(
                {
                    "agent": snapshot.agent,
                    "level": snapshot.level.name,
                    "level_value": int(
                        snapshot.level
                    ),
                    "event_count": snapshot.event_count,
                    "denial_count": snapshot.denial_count,
                    "escalation_count": (
                        snapshot.escalation_count
                    ),
                }
            )

    refusal_size = None

    if refusal is not None:
        try:
            refusal_size = refusal.size()
        except Exception:
            refusal_size = None

    return {
        "risk_tracked": risk is not None,
        "risk": risk_rows,
        "refusal_active": refusal is not None,
        "refusal_entries": refusal_size,
        "security_context_active": (
            security is not None
        ),
        "semantic_context_active": (
            semantic is not None
        ),
        "max_delegation_depth": (
            sdk.max_delegation_depth
        ),
    }
