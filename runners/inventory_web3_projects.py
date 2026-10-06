#!/usr/bin/env python3
"""Inventory evidence-based native build roots inside frozen Web3Bugs snapshots."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from runners.common import ROOT

SOURCE = ROOT / "benchmarks" / "sources" / "Web3Bugs" / "contracts"
EVIDENCE = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
OUTPUT = ROOT / "benchmarks" / "web3bugs" / "best_effort_project_inventory.csv"
FIELDS = (
    "snapshot_id", "project_root", "command", "command_evidence",
    "solidity_file_count", "selection_status",
)


def manager(root: Path, package: dict[str, object]) -> str:
    declared = str(package.get("packageManager", "")).split("@", 1)[0]
    if declared in {"npm", "yarn"}:
        return declared
    if (root / "yarn.lock").is_file():
        return "yarn"
    return "npm"


def command_for(root: Path) -> tuple[str, str] | None:
    package_path = root / "package.json"
    package: dict[str, object] = {}
    if package_path.is_file():
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            package = {}
        scripts = package.get("scripts", {})
        if isinstance(scripts, dict):
            for name in ("compile", "build"):
                value = scripts.get(name)
                if isinstance(value, str) and value.strip():
                    tool = manager(root, package)
                    command = f"yarn {name}" if tool == "yarn" else f"npm run {name}"
                    return command, f"nested package.json script {name}={value} at {root.name}"
    configs = (
        ("foundry.toml", "forge build"),
        ("hardhat.config.ts", "npx hardhat compile"),
        ("hardhat.config.js", "npx hardhat compile"),
        ("truffle-config.js", "npx truffle compile"),
        ("truffle.js", "npx truffle compile"),
        ("brownie-config.yaml", "brownie compile"),
        ("brownie-config.yml", "brownie compile"),
    )
    for filename, command in configs:
        if (root / filename).is_file():
            return command, f"checked-in nested {filename} at {root.name}"
    makefile = root / "Makefile"
    if makefile.is_file():
        text = makefile.read_text(encoding="utf-8", errors="replace")
        for target in ("compile", "build"):
            if any(line.startswith(f"{target}:") for line in text.splitlines()):
                return f"make {target}", f"checked-in Makefile target {target} at {root.name}"
    return None


def main() -> int:
    frozen = {
        row["snapshot_id"]: row["selection_status"]
        for row in json.loads(EVIDENCE.read_text(encoding="utf-8"))["snapshots"]
    }
    rows = []
    names = {
        "package.json", "foundry.toml", "hardhat.config.ts", "hardhat.config.js",
        "truffle-config.js", "truffle.js", "brownie-config.yaml",
        "brownie-config.yml", "Makefile",
    }
    for snapshot_id in sorted(frozen, key=int):
        snapshot = SOURCE / snapshot_id
        roots = set()
        for path in snapshot.rglob("*"):
            if path.name not in names or "node_modules" in path.parts or ".git" in path.parts:
                continue
            root = path.parent
            if list(root.rglob("*.sol")):
                roots.add(root)
        for root in sorted(roots, key=lambda item: item.relative_to(snapshot).as_posix()):
            selected = command_for(root)
            if not selected:
                continue
            command, evidence = selected
            rows.append({
                "snapshot_id": snapshot_id,
                "project_root": root.relative_to(snapshot).as_posix() or ".",
                "command": command,
                "command_evidence": evidence,
                "solidity_file_count": sum(1 for _ in root.rglob("*.sol")),
                "selection_status": frozen[snapshot_id],
            })
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    unresolved = [row for row in rows if not row["selection_status"].startswith("RESOLVED")]
    print(json.dumps({
        "project_rows": len(rows),
        "unresolved_snapshot_project_rows": len(unresolved),
        "unresolved_snapshots_with_native_projects": len(set(row["snapshot_id"] for row in unresolved)),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
