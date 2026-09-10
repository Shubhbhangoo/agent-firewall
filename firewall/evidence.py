from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


_SENSITIVE_KEYS = {
    "private_key",
    "private",
    "secret",
    "secret_key",
    "seed",
    "mnemonic",
    "password",
    "token",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}

        for key, item in value.items():
            key_text = str(key).lower()

            if any(
                sensitive in key_text
                for sensitive in _SENSITIVE_KEYS
            ):
                continue

            result[str(key)] = _sanitize(item)

        return result

    if isinstance(value, (list, tuple)):
        return [
            _sanitize(item)
            for item in value
        ]

    if isinstance(value, (set, frozenset)):
        sanitized = [
            _sanitize(item)
            for item in value
        ]

        return sorted(
            sanitized,
            key=lambda item: str(item),
        )

    if isinstance(
        value,
        (str, int, float, bool),
    ) or value is None:
        return value

    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _sanitize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


@dataclass(frozen=True)
class Evidence:
    decision: str
    reason: str

    agent_id: Optional[str] = None
    capability: Optional[str] = None

    namespace_match: Optional[bool] = None
    constraints_ok: Optional[bool] = None
    time_valid: Optional[bool] = None

    policy: Optional[str] = None
    request_id: Optional[str] = None

    details: Dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "namespace_match": self.namespace_match,
            "constraints_ok": self.constraints_ok,
            "time_valid": self.time_valid,
            "policy": self.policy,
            "request_id": self.request_id,
            "details": _sanitize(
                self.details
            ),
        }

    def to_json(self) -> str:
        return _canonical_json(
            self.to_dict()
        )

    def fingerprint(self) -> str:
        payload = self.to_json().encode(
            "utf-8"
        )

        return hashlib.sha256(
            payload
        ).hexdigest()


def make_evidence(
    decision: str,
    reason: str,
    *,
    agent_id: Optional[str] = None,
    capability: Optional[str] = None,
    namespace_match: Optional[bool] = None,
    constraints_ok: Optional[bool] = None,
    time_valid: Optional[bool] = None,
    policy: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Evidence:
    if not isinstance(
        decision,
        str,
    ) or not decision:
        raise ValueError(
            "decision must be a non-empty string"
        )

    if not isinstance(
        reason,
        str,
    ) or not reason:
        raise ValueError(
            "reason must be a non-empty string"
        )

    if details is None:
        details = {}

    if not isinstance(
        details,
        dict,
    ):
        raise TypeError(
            "details must be a dictionary"
        )

    return Evidence(
        decision=decision,
        reason=reason,
        agent_id=agent_id,
        capability=capability,
        namespace_match=namespace_match,
        constraints_ok=constraints_ok,
        time_valid=time_valid,
        policy=policy,
        request_id=request_id,
        details=dict(details),
    )


def allow_evidence(
    reason: str = "authorized",
    **kwargs,
) -> Evidence:
    return make_evidence(
        "allow",
        reason,
        **kwargs,
    )


def deny_evidence(
    reason: str,
    **kwargs,
) -> Evidence:
    return make_evidence(
        "deny",
        reason,
        **kwargs,
    )


def approval_evidence(
    reason: str = "approval required",
    **kwargs,
) -> Evidence:
    return make_evidence(
        "approval",
        reason,
        **kwargs,
    )


def evidence_from_dict(
    data: Dict[str, Any],
) -> Evidence:
    if not isinstance(
        data,
        dict,
    ):
        raise TypeError(
            "evidence data must be a dictionary"
        )

    details = data.get(
        "details",
        {},
    )

    if not isinstance(
        details,
        dict,
    ):
        raise TypeError(
            "evidence details must be a dictionary"
        )

    return Evidence(
        decision=data["decision"],
        reason=data["reason"],
        agent_id=data.get(
            "agent_id"
        ),
        capability=data.get(
            "capability"
        ),
        namespace_match=data.get(
            "namespace_match"
        ),
        constraints_ok=data.get(
            "constraints_ok"
        ),
        time_valid=data.get(
            "time_valid"
        ),
        policy=data.get(
            "policy"
        ),
        request_id=data.get(
            "request_id"
        ),
        details=dict(details),
    )