#!/usr/bin/env python3
"""Acquire exact native-config solc binaries from the pre-frozen official index."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

from runners.common import ROOT, sha256_file, write_json_new

INDEX = ROOT / "environment" / "acquisition" / "toolchain-indexes-001" / "solc-linux-amd64-list.json"
EVIDENCE = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
DESTINATION = ROOT / "environment" / "toolchains" / "solc"
INVENTORY = ROOT / "environment" / "compiler_inventory.json"
BASE_URL = "https://binaries.soliditylang.org/linux-amd64/"


def expected_builds(index):
    result = {}
    for build in index["builds"]:
        version = build.get("version")
        if version in index["releases"] and index["releases"][version] == build.get("path"):
            result[version] = build
    return result


def main() -> int:
    if DESTINATION.exists() or INVENTORY.exists():
        raise FileExistsError("refusing to overwrite compiler freeze")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    versions = sorted({
        version
        for snapshot in evidence["snapshots"]
        for values in snapshot["compiler_declarations"].values()
        for version in values
    }, key=lambda value: tuple(int(part) for part in value.split(".")))
    if not versions:
        raise RuntimeError("no exact native compiler declarations found")
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    builds = expected_builds(index)
    missing = sorted(set(versions) - set(builds))
    if missing:
        raise RuntimeError("official index lacks compiler versions: " + ",".join(missing))
    DESTINATION.mkdir(parents=True)
    records = []
    for version in versions:
        build = builds[version]
        directory = DESTINATION / version
        directory.mkdir()
        destination = directory / "solc"
        temporary = directory / "solc.partial"
        request = urllib.request.Request(
            BASE_URL + build["path"],
            headers={"User-Agent": "mvscan-f1-environment-freeze/1.0"},
        )
        with urllib.request.urlopen(request, timeout=300) as response, temporary.open("xb") as stream:
            shutil.copyfileobj(response, stream, length=1024 * 1024)
        actual = sha256_file(temporary)
        expected = build["sha256"].removeprefix("0x")
        if actual != expected:
            raise RuntimeError(f"solc {version} hash mismatch")
        os.replace(temporary, destination)
        destination.chmod(0o755)
        command = subprocess.run(
            [destination, "--version"], text=True, capture_output=True
        )
        if command.returncode or version not in command.stdout + command.stderr:
            raise RuntimeError(f"solc {version} version validation failed")
        records.append({
            "version": version,
            "platform": "linux/amd64",
            "relative_path": destination.relative_to(ROOT).as_posix(),
            "official_artifact": build["path"],
            "sha256": actual,
            "keccak256": build.get("keccak256"),
            "byte_size": destination.stat().st_size,
            "version_output": (command.stdout + command.stderr).strip(),
            "selection_evidence": "exact native build configuration",
        })
    unresolved = [
        snapshot["snapshot_id"]
        for snapshot in evidence["snapshots"]
        if not any(snapshot["compiler_declarations"].values())
    ]
    write_json_new(INVENTORY, {
        "schema_version": 1,
        "status": "UNRESOLVED" if unresolved else "COMPLETE",
        "frozen_before_detector_output": True,
        "official_index_relative_path": INDEX.relative_to(ROOT).as_posix(),
        "official_index_sha256": sha256_file(INDEX),
        "compilers": records,
        "unresolved_snapshot_ids": unresolved,
        "unresolved_reason": (
            "No exact native compiler declaration; pragma/source-completeness selection "
            "has not been authorized by the execution safety gate."
        ) if unresolved else None,
    })
    print(json.dumps({
        "compiler_binaries": len(records),
        "versions": versions,
        "unresolved_snapshots": len(unresolved),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
