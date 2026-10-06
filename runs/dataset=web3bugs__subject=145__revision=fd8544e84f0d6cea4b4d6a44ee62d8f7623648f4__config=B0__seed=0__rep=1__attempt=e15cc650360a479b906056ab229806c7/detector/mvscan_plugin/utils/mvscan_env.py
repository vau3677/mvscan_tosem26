"""
Environment parsing for MV-Scan
Options are parsed here; for safety, malformed values fail before analysis.
"""
from __future__ import annotations
import os
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}

# Parse a strict boolean env option
def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None: return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES: return True
    if normalized in _FALSE_VALUES: return False
    raise ValueError(f"{name} must be a bool value ({sorted(_TRUE_VALUES | _FALSE_VALUES)}), got {raw!r}")

# Parse a bounded integer env option
def env_int(name: str, default: int, minimum=None, maximum=None) -> int:
    raw = os.getenv(name)
    value = default if raw is None else int(raw.strip())
    if minimum is not None and value < minimum: raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum: raise ValueError(f"{name} must be <= {maximum}, got {value}")
    return value

# Parse a case-insensitive env choice from an allowed set
def env_enum(name: str, default: str, allowed) -> str:
    raw = os.getenv(name, default)
    normalized = raw.strip().lower()
    allowed_set = set(allowed)
    if normalized not in allowed_set: raise ValueError(f"{name}={raw!r} is invalid; expected one of {sorted(allowed_set)}")
    return normalized

# Parse a comma-separated env option into unique nonempty values
def env_csv(name: str): return frozenset(v.strip() for v in os.getenv(name, "").split(",") if v.strip())

# Reject misspelled or unsupported environment options under a prefix
def reject_unknown_prefixed_environment(prefix: str, known_names):
    unknown = sorted(name for name in os.environ if name.startswith(prefix) and name not in set(known_names))
    if unknown: raise ValueError(f"Unknown {prefix} config option(s): " + ", ".join(unknown))