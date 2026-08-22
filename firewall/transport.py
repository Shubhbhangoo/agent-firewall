from __future__ import annotations

import base64
import json
from typing import Any

from firewall.capability import Capability


TRANSPORT_VERSION = 1
DEFAULT_MAX_TOKEN_SIZE = 16 * 1024


class TransportError(ValueError):
    pass


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def encode_capability(
    capability: Capability,
    *,
    max_size: int = DEFAULT_MAX_TOKEN_SIZE,
) -> str:
    if not isinstance(
        capability,
        Capability,
    ):
        raise TypeError(
            "capability must be a Capability"
        )

    payload = {
        "v": TRANSPORT_VERSION,
        "capability": capability.to_dict(),
    }

    encoded = base64.urlsafe_b64encode(
        _canonical_json(payload)
    ).decode("ascii").rstrip("=")

    if len(encoded) > max_size:
        raise TransportError(
            "encoded capability exceeds maximum size"
        )

    return encoded


def decode_capability(
    token: str,
    *,
    max_size: int = DEFAULT_MAX_TOKEN_SIZE,
) -> Capability:
    if not isinstance(
        token,
        str,
    ):
        raise TypeError(
            "token must be a string"
        )

    if not token:
        raise TransportError(
            "token cannot be empty"
        )

    if len(token) > max_size:
        raise TransportError(
            "token exceeds maximum size"
        )

    if any(
        char not in
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_"
        for char in token
    ):
        raise TransportError(
            "token contains invalid base64url characters"
        )

    padded = token + (
        "=" * (-len(token) % 4)
    )

    try:
        raw = base64.urlsafe_b64decode(
            padded.encode("ascii")
        )
    except (
        ValueError,
        UnicodeEncodeError,
    ) as exc:
        raise TransportError(
            "invalid base64url token"
        ) from exc

    try:
        payload = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise TransportError(
            "invalid transport payload"
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise TransportError(
            "transport payload must be an object"
        )

    if payload.get("v") != TRANSPORT_VERSION:
        raise TransportError(
            "unsupported transport version"
        )

    capability_data = payload.get(
        "capability"
    )

    if not isinstance(
        capability_data,
        dict,
    ):
        raise TransportError(
            "missing capability object"
        )

    required_fields = {
        "agent_id",
        "capability",
        "constraints",
        "issuer",
        "issued_at",
        "expires_at",
        "public_key",
        "signature",
    }

    missing = required_fields - set(
        capability_data
    )

    if missing:
        raise TransportError(
            "missing capability fields: "
            + ", ".join(sorted(missing))
        )

    try:
        return Capability(
            **capability_data
        )
    except (
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise TransportError(
            "invalid capability object"
        ) from exc


def round_trip(
    capability: Capability,
    *,
    max_size: int = DEFAULT_MAX_TOKEN_SIZE,
) -> Capability:
    return decode_capability(
        encode_capability(
            capability,
            max_size=max_size,
        ),
        max_size=max_size,
    )


def token_size(
    capability: Capability,
) -> int:
    return len(
        encode_capability(
            capability
        )
    )


def is_transport_token(
    value: Any,
) -> bool:
    if not isinstance(
        value,
        str,
    ):
        return False

    if not value:
        return False

    try:
        decode_capability(value)
        return True
    except (
        TypeError,
        TransportError,
    ):
        return False