#!/usr/bin/env python3
"""Finalize compiler inventory after all accepted subject manifests exist."""
from __future__ import annotations

import json
import os
from pathlib import Path

from runners.common import ROOT, sha256_file


def replace(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    svm_path = ROOT / "environment/frozen_svm_compilers.json"
    inventory_path = ROOT / "environment/compiler_inventory.json"
    svm = json.loads(svm_path.read_text(encoding="utf-8"))
    external = ROOT / "environment/frozen_compilers/0.8.36/solc-0.8.36"
    external_record = {
        "version": "0.8.36",
        "path": "/mnt/compiler-bin/solc",
        "source_path": "environment/frozen_compilers/0.8.36/solc-0.8.36",
        "sha256": sha256_file(external),
    }
    compilers = [row for row in svm["compilers"] if row.get("version") != "0.8.36"]
    compilers.append(external_record)
    compilers.sort(key=lambda row: tuple(int(part) for part in row["version"].split(".")))
    svm["compilers"] = compilers
    svm["source"] = "accepted build attempt SVM caches, frozen toolchains, and verified official external compiler archive"
    replace(svm_path, svm)

    previous = json.loads(inventory_path.read_text(encoding="utf-8"))
    detailed = {row["version"]: row for row in previous.get("compilers", [])}
    for row in compilers:
        if row["version"] in detailed:
            continue
        source_path = row.get("source_path")
        if source_path:
            binary = ROOT / source_path
            relative = source_path
        else:
            binary = ROOT / "environment/oci-rootfs" / row["path"].lstrip("/")
            relative = binary.relative_to(ROOT).as_posix()
        detailed[row["version"]] = {
            "version": row["version"],
            "platform": "linux/amd64",
            "relative_path": relative,
            "byte_size": binary.stat().st_size,
            "sha256": sha256_file(binary),
            "selection_evidence": "exact compiler required by an accepted execution-subject artifact",
        }
    manifests = sorted((ROOT / "benchmarks/subject_manifests").glob("*.json"))
    if len(manifests) != 153:
        raise RuntimeError("compiler inventory requires exactly 153 subject manifests")
    requested = set()
    for path in manifests:
        document = json.loads(path.read_text(encoding="utf-8"))
        command = document.get("analysis_command", [])
        if "--solc" in command:
            requested.add(Path(command[command.index("--solc") + 1]).parent.name)
    available = {row["version"] for row in compilers}
    if not requested <= available:
        raise RuntimeError("subject manifests request unavailable solc versions: " + repr(sorted(requested - available)))
    inventory = {
        "schema_version": 1,
        "status": "COMPLETE",
        "frozen_before_detector_output": True,
        "official_index_relative_path": previous.get("official_index_relative_path"),
        "official_index_sha256": previous.get("official_index_sha256"),
        "compilers": [detailed[key] for key in sorted(detailed, key=lambda value: tuple(int(part) for part in value.split(".")))],
        "execution_subject_coverage": {
            "subject_manifests": len(manifests),
            "explicit_standard_json_versions": sorted(requested, key=lambda value: tuple(int(part) for part in value.split("."))),
            "all_requested_versions_available": True,
        },
    }
    replace(inventory_path, inventory)
    print(json.dumps({"status": "COMPLETE", "frozen_compilers": len(compilers), "subject_manifests": len(manifests)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
