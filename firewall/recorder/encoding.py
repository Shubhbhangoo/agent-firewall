"""Canonical encoding for the agent security artifact.

Every byte that is hashed or signed in the v1.8 format is produced by
:func:`canonical_bytes`. The encoding is deliberately boring and fully
documented so that a verifier written in another language can reproduce
it byte for byte:

* JSON, UTF-8.
* Object keys sorted in Unicode code-point order (``sort_keys=True``).
* No whitespace: items separated by ``,``, key/value pairs by ``:``.
* Non-ASCII characters written literally (``ensure_ascii=False``).
* Numbers: integers serialized as integers, floats serialized with
  Python's shortest round-trip representation. A value that parses back
  to the same float serializes to the same bytes on any platform.
* ``NaN``, positive infinity, and negative infinity are rejected
  everywhere -- the format never contains them.

Because the encoding is a pure function of the *value* (not of the file
bytes), a recorder and a verifier on different machines compute the same
hash for the same event, and an artifact can be re-serialized from its
parsed JSON and still verify.
"""

from __future__ import annotations

import json
import math
from typing import Any

#: Canonical JSON is compact and key-sorted. These are the exact
#: separators: no spaces, so a hash never depends on formatting.
_SEPARATORS = (",", ":")


class EncodingError(ValueError):
    """Raised when a value cannot be canonically encoded."""


def _check_finite(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(
        value, (int, float)
    ):
        return

    if isinstance(value, float):
        if not math.isfinite(value):
            raise EncodingError(
                "non-finite numbers are not allowed in the "
                "security artifact"
            )


def _check_tree(
    value: Any,
    *,
    depth: int,
    max_depth: int,
) -> None:
    if depth > max_depth:
        raise EncodingError(
            f"payload nesting exceeds {max_depth} levels"
        )

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EncodingError(
                    "payload object keys must be strings"
                )
            _check_tree(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return

    if isinstance(value, (list, tuple)):
        for item in value:
            _check_tree(
                item,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return

    if value is None or isinstance(
        value, (str, bool)
    ):
        return

    if isinstance(value, (int, float)):
        _check_finite(value)
        return

    raise EncodingError(
        f"value of type {type(value).__name__} is not "
        "representable in the security artifact"
    )


def validate_artifact_value(
    value: Any,
    *,
    max_depth: int = 12,
) -> None:
    """Reject values the canonical encoder cannot represent.

    Runs before hashing so a recorder can never emit an event that a
    verifier could not re-encode byte for byte.
    """

    _check_tree(
        value,
        depth=0,
        max_depth=max_depth,
    )


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``.

    Deterministic across processes and platforms for every value the
    format allows. Raises :class:`EncodingError` for anything else, so a
    hash or signature is never computed over ambiguous bytes.
    """

    validate_artifact_value(value)

    return json.dumps(
        value,
        sort_keys=True,
        separators=_SEPARATORS,
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 digest of ``data``."""

    import hashlib

    return hashlib.sha256(data).hexdigest()
