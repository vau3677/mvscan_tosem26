from __future__ import annotations

import os
from collections.abc import Collection


_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be a boolean value "
        f"({sorted(_TRUE_VALUES | _FALSE_VALUES)}), got {raw!r}"
    )


def env_enum(name: str, default: str, allowed: Collection[str]) -> str:
    raw = os.getenv(name, default)
    normalized = raw.strip().lower()
    allowed_set = set(allowed)
    if normalized not in allowed_set:
        raise ValueError(
            f"{name}={raw!r} is invalid; expected one of {sorted(allowed_set)}"
        )
    return normalized


def env_csv(name: str) -> frozenset[str]:
    return frozenset(
        value.strip()
        for value in os.getenv(name, "").split(",")
        if value.strip()
    )


def reject_unknown_prefixed_environment(
    prefix: str,
    known_names: Collection[str],
) -> None:
    known = set(known_names)
    unknown = sorted(
        name for name in os.environ
        if name.startswith(prefix) and name not in known
    )
    if unknown:
        raise ValueError(
            f"Unknown {prefix} configuration option(s): " + ", ".join(unknown)
        )
