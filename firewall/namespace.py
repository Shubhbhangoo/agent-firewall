from __future__ import annotations

import re


_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def validate_namespace(namespace: str) -> bool:
    if not isinstance(namespace, str):
        return False

    if not namespace:
        return False

    if namespace.startswith("."):
        return False

    if namespace.endswith("."):
        return False

    if ".." in namespace:
        return False

    parts = namespace.split(".")

    wildcard_seen = False

    for index, part in enumerate(parts):
        if part == "*":
            # Only one wildcard is allowed and it must
            # be the final segment.
            if wildcard_seen:
                return False

            if index != len(parts) - 1:
                return False

            wildcard_seen = True
            continue

        if not _SEGMENT_RE.fullmatch(part):
            return False

    return True


def _parts(namespace: str) -> list[str]:
    if not validate_namespace(namespace):
        raise ValueError(
            f"invalid namespace: {namespace!r}"
        )

    return namespace.split(".")


def is_wildcard(namespace: str) -> bool:
    return (
        validate_namespace(namespace)
        and namespace.endswith(".*")
    )


def namespace_depth(namespace: str) -> int:
    return len(_parts(namespace))


def matches(
    pattern: str,
    action: str,
) -> bool:
    """
    Determine whether a capability namespace authorizes
    a concrete action.
    """

    if not validate_namespace(pattern):
        return False

    if not validate_namespace(action):
        return False

    pattern_parts = _parts(pattern)
    action_parts = _parts(action)

    # An action must always be concrete.
    if "*" in action_parts:
        return False

    if len(pattern_parts) > len(action_parts):
        return False

    for index, pattern_part in enumerate(pattern_parts):
        if pattern_part == "*":
            # Final wildcard matches one or more descendants.
            return index < len(action_parts)

        if pattern_part != action_parts[index]:
            return False

    return len(pattern_parts) == len(action_parts)


def is_narrower(
    child: str,
    parent: str,
) -> bool:
    """
    Return True when child grants no more authority
    than parent.
    """

    if not validate_namespace(child):
        return False

    if not validate_namespace(parent):
        return False

    if child == parent:
        return True

    child_parts = _parts(child)
    parent_parts = _parts(parent)

    if parent_parts[-1] == "*":
        parent_prefix = parent_parts[:-1]

        if len(child_parts) <= len(parent_prefix):
            return False

        return (
            child_parts[:len(parent_prefix)]
            == parent_prefix
        )

    return False


def is_broader(
    parent: str,
    child: str,
) -> bool:
    return is_narrower(
        child,
        parent,
    )


def parent_namespace(
    namespace: str,
) -> str | None:
    if not validate_namespace(namespace):
        raise ValueError(
            f"invalid namespace: {namespace!r}"
        )

    parts = _parts(namespace)

    if len(parts) <= 1:
        return None

    return ".".join(parts[:-1])


def namespace_contains(
    parent: str,
    child: str,
) -> bool:
    return is_narrower(
        child,
        parent,
    )


def normalize_namespace(
    namespace: str,
) -> str:
    if not isinstance(namespace, str):
        raise ValueError(
            "namespace must be a string"
        )

    normalized = namespace.strip()

    if not validate_namespace(normalized):
        raise ValueError(
            f"invalid namespace: {namespace!r}"
        )

    return normalized