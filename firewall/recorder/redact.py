"""Redaction of sensitive values before they enter the security history.

The recorder never records secrets on purpose, but "never on purpose" is
not a security boundary -- a payload field can *look* innocuous to the
calling code and still carry a credential. This module is the safety
net: a deterministic, recursive scan that replaces values under
credential-shaped key names with a placeholder and records exactly what
was replaced and why.

Redaction happens *before* hashing, so the chain itself never contains
the removed bytes. The artifact carries a ``redactions`` manifest listing
every replaced field path, which lets a verifier report the artifact as
``redacted`` -- integrity intact, content deliberately missing -- rather
than silently treating missing evidence as trustworthy.
"""

from __future__ import annotations

from typing import Any

#: Key names whose values are treated as secrets. Deliberately specific:
#: broad words like "token" or "key" would redact legitimate facts such
#: as a capability named ``token.read`` or a policy key.
SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "private_key",
    "private-key",
    "api_key",
    "api-key",
    "apikey",
    "access_token",
    "access-token",
    "auth_token",
    "auth-token",
    "refresh_token",
    "refresh-token",
    "bearer",
    "authorization",
    "cookie",
    "session_token",
    "session-token",
    "seed_phrase",
    "mnemonic",
    "credential",
    "client_secret",
    "client-secret",
)

#: The canonical placeholder. Never a plausible real value.
REDACTED_PLACEHOLDER = "[REDACTED]"

#: Maximum number of redactions recorded per payload, so a hostile or
#: pathological payload cannot grow the manifest without bound.
MAX_REDACTIONS = 128


class RedactionError(ValueError):
    """Raised for a malformed redaction request."""


def _path_of(
    segments: tuple[str, ...],
) -> str:
    return ".".join(segments)


def _is_sensitive_key(
    key: Any,
    sensitive_keywords: tuple[str, ...],
) -> bool:
    if not isinstance(key, str):
        return False

    lowered = key.lower().replace("-", "_")

    return any(
        keyword in lowered
        for keyword in sensitive_keywords
    )


def redact_payload(
    payload: Any,
    *,
    sensitive_keys: Any = None,
    reason: str = "sensitive value",
    placeholder: str = REDACTED_PLACEHOLDER,
) -> tuple[Any, list[dict[str, str]]]:
    """Return ``(redacted, redactions)`` for ``payload``.

    ``redactions`` is a list of ``{"path": ..., "reason": ...}`` entries,
    one per replaced value, capped at :data:`MAX_REDACTIONS`. The
    structure of the payload is preserved; only credential-shaped values
    are replaced. A non-mapping payload is returned unchanged.
    """

    if not isinstance(reason, str) or not reason.strip():
        raise RedactionError(
            "reason must be a non-empty string"
        )

    keywords = tuple(
        SENSITIVE_KEYWORDS
        if sensitive_keys is None
        else sensitive_keys
    )

    redactions: list[dict[str, str]] = []

    def walk(
        value: Any,
        segments: tuple[str, ...],
    ) -> Any:
        if len(redactions) >= MAX_REDACTIONS:
            # Keep structure, stop collecting. The scan is best-effort;
            # anything beyond the cap stays untouched rather than
            # stalling the recorder.
            return value

        if isinstance(value, dict):
            out: dict[str, Any] = {}

            for key, item in value.items():
                if _is_sensitive_key(
                    key, keywords
                ):
                    out[str(key)] = placeholder
                    redactions.append(
                        {
                            "path": _path_of(
                                (*segments, str(key))
                            ),
                            "reason": reason,
                        }
                    )
                    if len(redactions) >= MAX_REDACTIONS:
                        # Copy the rest verbatim and stop recording.
                        for rest_key, rest_value in value.items():
                            if rest_key not in out:
                                out[str(rest_key)] = rest_value
                        break
                    continue

                out[str(key)] = walk(
                    item,
                    (*segments, str(key)),
                )

            return out

        if isinstance(value, (list, tuple)):
            return [
                walk(
                    item,
                    (*segments, str(index)),
                )
                for index, item in enumerate(value)
            ]

        return value

    redacted = walk(payload, ())

    return redacted, redactions
