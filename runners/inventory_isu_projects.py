#!/usr/bin/env python3
"""Inventory evidence-backed native build roots in acquired ISU sources."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import re

from runners.common import ROOT

ACQUISITION = ROOT / "benchmarks" / "isu" / "source_acquisition_best_effort.csv"
OUTPUT = ROOT / "benchmarks" / "isu" / "best_effort_project_inventory.csv"
FIELDS = (
    "source_id", "repository", "requested_revision", "checkout_revision",
    "project_root", "command", "command_evidence", "solidity_file_count",
    "node_profile", "node_selection_evidence",
)


def package_manager(root: Path, package: dict[str, object]) -> str:
    declared = str(package.get("packageManager", "")).split("@", 1)[0]
    if declared in {"npm", "yarn"}:
        return declared
    if (root / "yarn.lock").is_file():
        return "yarn"
    return "npm"


def node_profile(root: Path, package: dict[str, object]) -> tuple[str, str]:
    candidates = []
    engines = package.get("engines", {})
    if isinstance(engines, dict) and engines.get("node"):
        candidates.append((str(engines["node"]), "package.json engines.node"))
    for name in (".nvmrc", ".node-version"):
        path = root / name
        if path.is_file():
            candidates.append((path.read_text(encoding="utf-8", errors="replace").strip(), name))
    if candidates:
        value, evidence = candidates[0]
        match = re.search(r"(?<!\d)(\d{1,2})(?:\.\d+)?", value)
        major = int(match.group(1)) if match else 16
        if major <= 12:
            return "node12-yarn1", f"{evidence}={value}"
        if major <= 14:
            return "node14-yarn1" if package_manager(root, package) == "yarn" else "node14-npm6", f"{evidence}={value}"
        return "node16-yarn1" if package_manager(root, package) == "yarn" else "node16-npm8", f"{evidence}={value}; nearest archived major"
    manager = package_manager(root, package)
    return ("node16-yarn1" if manager == "yarn" else "node16-npm8", "best-effort fallback; no checked-in Node version evidence")


def command_for(root: Path) -> tuple[str, str, str, str] | None:
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
                    manager = package_manager(root, package)
                    command = f"yarn {name}" if manager == "yarn" else f"npm run {name}"
                    profile, node_evidence = node_profile(root, package)
                    return command, f"checked-in package.json script {name}={value}", profile, node_evidence
    configs = (
        ("foundry.toml", "forge build"),
        ("hardhat.config.ts", "npx hardhat compile"),
        ("hardhat.config.js", "npx hardhat compile"),
        ("truffle-config.js", "npx truffle compile"),
        ("truffle.js", "npx truffle compile"),
        ("brownie-config.yaml", "brownie compile"),
        ("brownie-config.yml", "brownie compile"),
    )
    profile, node_evidence = node_profile(root, package)
    for filename, command in configs:
        if (root / filename).is_file():
            return command, f"checked-in {filename}", profile, node_evidence
    makefile = root / "Makefile"
    if makefile.is_file():
        text = makefile.read_text(encoding="utf-8", errors="replace")
        for target in ("compile", "build"):
            if re.search(rf"(?m)^\s*{target}\s*:", text):
                return f"make {target}", f"checked-in Makefile target {target}", profile, node_evidence
    return None


def main() -> int:
    with ACQUISITION.open(newline="", encoding="utf-8") as stream:
        acquired = [row for row in csv.DictReader(stream) if row["status"].startswith("ACQUIRED")]
    rows: list[dict[str, object]] = []
    names = {
        "package.json", "foundry.toml", "hardhat.config.ts", "hardhat.config.js",
        "truffle-config.js", "truffle.js", "brownie-config.yaml",
        "brownie-config.yml", "Makefile",
    }
    sources_with_solidity = set()
    for source in acquired:
        source_root = ROOT / source["source_path"]
        roots = set()
        for path in source_root.rglob("*"):
            if path.name not in names or "node_modules" in path.parts or ".git" in path.parts:
                continue
            root = path.parent
            if any(p.is_file() for p in root.rglob("*.sol")):
                roots.add(root)
                sources_with_solidity.add(source["source_id"])
        for root in sorted(roots, key=lambda item: item.relative_to(source_root).as_posix()):
            selected = command_for(root)
            if not selected:
                continue
            command, evidence, profile, node_evidence = selected
            rows.append({
                "source_id": source["source_id"],
                "repository": source["repository"],
                "requested_revision": source["requested_revision"],
                "checkout_revision": source["checkout_revision"],
                "project_root": root.relative_to(source_root).as_posix() or ".",
                "command": command,
                "command_evidence": evidence,
                "solidity_file_count": sum(1 for p in root.rglob("*.sol") if p.is_file()),
                "node_profile": profile,
                "node_selection_evidence": node_evidence,
            })
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    inventoried = {str(row["source_id"]) for row in rows}
    print(json.dumps({
        "acquired_sources": len(acquired),
        "project_rows": len(rows),
        "sources_with_native_project": len(inventoried),
        "sources_with_solidity_but_no_native_project": len(sources_with_solidity - inventoried),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
