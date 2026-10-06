#!/usr/bin/env python3
"""Freeze Web3Bugs build evidence without reading Solidity source bodies."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import re

from runners.common import ROOT, sha256_file, write_json_new

SOURCE_ROOT = ROOT / "benchmarks" / "sources" / "Web3Bugs" / "contracts"
POPULATION = ROOT / "benchmarks" / "web3bugs" / "population.csv"
OUTPUT = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
METADATA_NAMES = (
    "README.md", "readme.md", "package.json", "package-lock.json",
    "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", ".nvmrc",
    ".node-version", "hardhat.config.js", "hardhat.config.ts", "foundry.toml",
    "truffle-config.js", "brownie-config.yaml", "Makefile",
)
COMMAND_PREFIXES = (
    "npm ", "npx ", "yarn ", "pnpm ", "forge ", "hardhat ",
    "truffle ", "brownie ", "make ",
)


def population_rows():
    with POPULATION.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def command_lines(text: str) -> list[str]:
    fence = chr(96) * 3
    blocks = text.split(fence)[1::2]
    commands = set()
    for block in blocks:
        lines = block.splitlines()
        if lines and lines[0].strip().lower() in {"bash", "sh", "shell", "console"}:
            lines = lines[1:]
        for raw in lines:
            line = raw.strip()
            if line.startswith("$"):
                line = line[1:].strip()
            if line.startswith(COMMAND_PREFIXES):
                commands.add(line)
    return sorted(commands)


def hardhat_solidity_versions(text: str) -> list[str]:
    versions = set()
    for match in re.finditer(r"solidity\s*:", text):
        cursor = match.end()
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor < len(text) and text[cursor] in {chr(34), chr(39)}:
            quote = text[cursor]
            end = text.find(quote, cursor + 1)
            value = text[cursor + 1:end] if end != -1 else ""
            if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
                versions.add(value)
            continue
        if cursor >= len(text) or text[cursor] != "{":
            continue
        depth, end = 0, cursor
        while end < len(text):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        block = text[cursor:end + 1]
        versions.update(re.findall(r"version\s*:\s*[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)", block))
    return sorted(versions)


def compiler_declarations(name: str, text: str) -> list[str]:
    if name.startswith("hardhat.config"):
        return hardhat_solidity_versions(text)
    patterns = []
    if name == "foundry.toml":
        patterns = [r"(?m)^\s*solc(?:_version)?\s*=\s*[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    elif name == "truffle-config.js":
        patterns = [r"version\s*:\s*[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    elif name == "brownie-config.yaml":
        patterns = [
            r"(?m)^\s*version\s*:\s*[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)",
            r"(?m)^\s*solc\s*:\s*[^0-9\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        ]
    return sorted({value for pattern in patterns for value in re.findall(pattern, text)})


def manager_for(files: set[str], package: dict[str, object]) -> tuple[str | None, str]:
    declaration = package.get("packageManager")
    if isinstance(declaration, str) and declaration:
        return declaration.split("@", 1)[0], "packageManager"
    for lock, manager in (
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("npm-shrinkwrap.json", "npm"),
    ):
        if lock in files:
            return manager, "lockfile"
    return None, "none"


def native_commands(files: set[str]):
    result = []
    if {"hardhat.config.js", "hardhat.config.ts"} & files:
        result.append(("npx hardhat compile", "checked-in Hardhat configuration"))
    if "foundry.toml" in files:
        result.append(("forge build", "checked-in Foundry configuration"))
    if "truffle-config.js" in files:
        result.append(("npx truffle compile", "checked-in Truffle configuration"))
    if "brownie-config.yaml" in files:
        result.append(("brownie compile", "checked-in Brownie configuration"))
    if "Makefile" in files:
        result.append(("make", "checked-in Makefile"))
    return result


def main() -> int:
    if OUTPUT.exists():
        raise FileExistsError("refusing to overwrite Web3Bugs build evidence")
    population = population_rows()
    if len(population) != 102:
        raise RuntimeError("Web3Bugs population count mismatch")
    snapshots = []
    for population_row in sorted(population, key=lambda row: int(row["snapshot_id"])):
        snapshot_id = population_row["snapshot_id"]
        directory = SOURCE_ROOT / snapshot_id
        metadata, texts = {}, {}
        for name in METADATA_NAMES:
            path = directory / name
            if not path.is_file():
                continue
            metadata[name] = {"sha256": sha256_file(path), "byte_size": path.stat().st_size}
            if name.endswith((".md", ".json", ".js", ".ts", ".toml", ".yaml")) or name in {".nvmrc", ".node-version", "Makefile"}:
                texts[name] = path.read_text(encoding="utf-8", errors="replace")
        files = set(metadata)
        package, package_error = {}, None
        if "package.json" in texts:
            try:
                package = json.loads(texts["package.json"])
            except json.JSONDecodeError as exc:
                package_error = str(exc)
        manager, manager_evidence = manager_for(files, package)
        lock_version = None
        if "package-lock.json" in texts:
            try:
                lock_version = json.loads(texts["package-lock.json"]).get("lockfileVersion")
            except json.JSONDecodeError:
                lock_version = "INVALID_JSON"
        readme_commands = sorted({
            command
            for name in ("README.md", "readme.md")
            if name in texts
            for command in command_lines(texts[name])
        })
        ci_files, ci_commands = [], []
        for path in sorted(directory.glob(".github/workflows/*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            ci_files.append({
                "relative_path": path.relative_to(directory).as_posix(),
                "sha256": sha256_file(path),
                "byte_size": path.stat().st_size,
            })
            ci_commands.extend(
                line.strip()[4:].strip()
                for line in text.splitlines()
                if line.strip().startswith("run:")
            )
        candidates = []
        for command in sorted(set(ci_commands + readme_commands)):
            lowered = command.lower()
            if "compile" in lowered or re.search(r"(^|\s)build($|\s)", lowered):
                candidates.append({"rank": 1, "command": command, "evidence": "documented CI or README command"})
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        if not isinstance(scripts, dict):
            scripts = {}
        if manager:
            for script_name, script_value in sorted(scripts.items()):
                if script_name.lower() in {"compile", "build"}:
                    command = f"npm run {script_name}" if manager == "npm" else f"{manager} {script_name}"
                    candidates.append({
                        "rank": 2,
                        "command": command,
                        "evidence": f"package.json script {script_name}={script_value}",
                    })
        for command, evidence in native_commands(files):
            candidates.append({"rank": 3, "command": command, "evidence": evidence})
        lowest_rank = min((row["rank"] for row in candidates), default=None)
        lowest_commands = (
            sorted({row["command"] for row in candidates if row["rank"] == lowest_rank})
            if lowest_rank is not None else []
        )
        selected = lowest_commands[0] if len(lowest_commands) == 1 else None
        status = (
            "RESOLVED" if selected else
            "UNRESOLVED_NO_BUILD_EVIDENCE" if not candidates else
            "UNRESOLVED_AMBIGUOUS_BUILD_EVIDENCE"
        )
        compiler = {
            name: compiler_declarations(name, text)
            for name, text in texts.items()
            if name in {"hardhat.config.js", "hardhat.config.ts", "foundry.toml", "truffle-config.js", "brownie-config.yaml"}
        }
        snapshots.append({
            "snapshot_id": snapshot_id,
            "snapshot_sha256": population_row["snapshot_sha256"],
            "metadata_files": metadata,
            "ci_files": ci_files,
            "package_json_error": package_error,
            "package_manager_declaration": package.get("packageManager") if isinstance(package, dict) else None,
            "engines": package.get("engines", {}) if isinstance(package, dict) else {},
            "package_manager_family": manager,
            "package_manager_evidence": manager_evidence,
            "package_lock_version": lock_version,
            "nvmrc": texts.get(".nvmrc", "").strip() or None,
            "node_version_file": texts.get(".node-version", "").strip() or None,
            "scripts": scripts,
            "readme_commands": readme_commands,
            "ci_commands": sorted(set(ci_commands)),
            "compiler_declarations": compiler,
            "build_command_candidates": candidates,
            "selected_build_command": selected,
            "selected_evidence_rank": lowest_rank if selected else None,
            "selection_status": status,
            "solidity_source_bodies_read": False,
        })
    write_json_new(OUTPUT, {
        "schema_version": 1,
        "repository_commit": "fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4",
        "evidence_order": [
            "documented CI or README command",
            "declared package-manager compile/build script",
            "checked-in native build system",
            "direct crytic-compile or standard JSON only when source completeness is established",
        ],
        "metadata_only": True,
        "solidity_source_bodies_read": False,
        "snapshots": snapshots,
    })
    counts = {}
    for row in snapshots:
        counts[row["selection_status"]] = counts.get(row["selection_status"], 0) + 1
    print(json.dumps({"snapshots": len(snapshots), "selection_status_counts": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
