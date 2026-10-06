from __future__ import annotations
from pathlib import Path
from runners.common import ROOT

CONFIG_NAMES = ("B0", "A1", "A2", "A4", "A5")
BOOL_NAMES = {"MVSCAN_STRICT_CONFIG", "MVSCAN_INCLUDE_SCALAR_WITNESSES", "MVSCAN_CONTEXTUAL_KEYS", "MVSCAN_INTERFACE_DISPATCH", "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS", "MVSCAN_ROOT_CONTEXT_SINKS", "NOOP_WRITE_FILTER", "REQUIRE_SAME_SLOT_KEY", "MERGE_OVERLOADS"}
INT_NAMES = {"MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK", "MVSCAN_MAX_DISPATCH_TARGETS", "DIVERGENCE_BUDGET"}
CSV_NAMES = {"USER_CALLABLE_ALWAYS", "USER_CALLABLE_DENY", "ATOMIC_GROUP"}
ENUMS = {"MVSCAN_ABLATION": {"full", "no_branch_groups", "no_multi_return_groups", "mapping_insensitive"}, "SINK_TEST": {"none"}}
REQUIRED_NAMES = BOOL_NAMES | INT_NAMES | CSV_NAMES | set(ENUMS)
B0_EXPECTED = {
    "MVSCAN_STRICT_CONFIG": "1",
    "MVSCAN_ABLATION": "full",
    "MVSCAN_INCLUDE_SCALAR_WITNESSES": "0",
    "MVSCAN_CONTEXTUAL_KEYS": "1",
    "MVSCAN_INTERFACE_DISPATCH": "0",
    "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS": "0",
    "MVSCAN_ROOT_CONTEXT_SINKS": "0",
    "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK": "128",
    "MVSCAN_MAX_DISPATCH_TARGETS": "16",
    "SINK_TEST": "none",
    "DIVERGENCE_BUDGET": "1000",
    "NOOP_WRITE_FILTER": "1",
    "REQUIRE_SAME_SLOT_KEY": "1",
    "USER_CALLABLE_ALWAYS": "",
    "USER_CALLABLE_DENY": "",
    "ATOMIC_GROUP": "",
    "MERGE_OVERLOADS": "0",
}
CONFIGURATION_OVERRIDES = {
    "B0": {},
    "A1": {"MVSCAN_ABLATION": "no_branch_groups"},
    "A2": {"MVSCAN_ABLATION": "no_multi_return_groups"},
    "A4": {"MVSCAN_ABLATION": "mapping_insensitive"},
    "A5": {"MVSCAN_CONTEXTUAL_KEYS": "0"},
}

def parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.lstrip().startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError(f"{path}:{line_number}: expected NAME=VALUE")
        name, value = raw.split("=", 1)
        if not name or name.strip() != name or name in result:
            raise ValueError(f"{path}:{line_number}: invalid or duplicate name")
        result[name] = value
    unknown_mvscan = sorted(name for name in result if name.startswith("MVSCAN_") and name not in REQUIRED_NAMES)
    if unknown_mvscan:
        raise ValueError("unknown MVSCAN variables: " + ", ".join(unknown_mvscan))
    missing, extra = sorted(REQUIRED_NAMES - result.keys()), sorted(result.keys() - REQUIRED_NAMES)
    if missing or extra:
        raise ValueError(f"configuration names differ: missing={missing}, extra={extra}")
    for name in BOOL_NAMES:
        if result[name] not in {"0", "1"}:
            raise ValueError(f"{name} must be 0 or 1")
    for name in INT_NAMES:
        try:
            value = int(result[name])
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if value < 0:
            raise ValueError(f"{name} must be nonnegative")
    for name, allowed in ENUMS.items():
        if result[name] not in allowed:
            raise ValueError(f"{name} must be one of {sorted(allowed)}")
    return result

def expected_named(name: str) -> dict[str, str]:
    if name not in CONFIG_NAMES:
        raise ValueError(f"configuration must be one of {CONFIG_NAMES}")
    return {**B0_EXPECTED, **CONFIGURATION_OVERRIDES[name]}

def load_named(name: str) -> dict[str, str]:
    actual = parse_env(ROOT / "configs" / f"{name}.env")
    expected = expected_named(name)
    if actual != expected:
        differing = sorted(
            key for key in REQUIRED_NAMES if actual.get(key) != expected.get(key)
        )
        raise ValueError(
            f"{name} differs from the frozen configuration at: {differing}"
        )
    return actual

def detector_effective_config(config: dict[str, str]) -> dict[str, object]:
    ablation = config["MVSCAN_ABLATION"]
    def csv(name: str) -> list[str]:
        return sorted(value.strip() for value in config[name].split(",") if value.strip())
    return {
        "ATOMIC_GROUP": csv("ATOMIC_GROUP"), "DIVERGENCE_BUDGET": int(config["DIVERGENCE_BUDGET"]),
        "ENABLE_BRANCH_GROUPS": ablation != "no_branch_groups", "ENABLE_EXTERNAL_STATE": True,
        "ENABLE_MULTI_RETURN_GROUPS": ablation != "no_multi_return_groups",
        "MAPPING_MODE": "base_collapsed" if ablation == "mapping_insensitive" else "precise",
        "MERGE_OVERLOADS": config["MERGE_OVERLOADS"] == "1", "MVSCAN_ABLATION": ablation,
        "MVSCAN_CONTEXTUAL_KEYS": config["MVSCAN_CONTEXTUAL_KEYS"] == "1",
        "MVSCAN_INCLUDE_SCALAR_WITNESSES": config["MVSCAN_INCLUDE_SCALAR_WITNESSES"] == "1",
        "MVSCAN_INTERFACE_DISPATCH": config["MVSCAN_INTERFACE_DISPATCH"] == "1",
        "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK": int(config["MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK"]),
        "MVSCAN_MAX_DISPATCH_TARGETS": int(config["MVSCAN_MAX_DISPATCH_TARGETS"]),
        "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS": config["MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS"] == "1",
        "MVSCAN_ROOT_CONTEXT_SINKS": config["MVSCAN_ROOT_CONTEXT_SINKS"] == "1",
        "NOOP_WRITE_FILTER": config["NOOP_WRITE_FILTER"] == "1",
        "REQUIRE_SAME_SLOT_KEY": config["REQUIRE_SAME_SLOT_KEY"] == "1" and ablation != "mapping_insensitive",
        "SINK_TEST": config["SINK_TEST"], "USER_CALLABLE_ALWAYS": csv("USER_CALLABLE_ALWAYS"),
        "USER_CALLABLE_DENY": csv("USER_CALLABLE_DENY"),
    }
