#!/usr/bin/env python3
"""Acquire and freeze Node/package-manager profiles selected from project metadata."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

from runners.common import ROOT, sha256_file, tree_digest, write_json_new

INDEX_ROOT = ROOT / "environment" / "acquisition" / "toolchain-indexes-001"
NODE_INDEX = INDEX_ROOT / "node-index.json"
YARN_INDEX = INDEX_ROOT / "yarn-registry.json"
EVIDENCE = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
ARCHIVES = ROOT / "environment" / "acquisition" / "node-toolchains-001"
TOOLCHAINS = ROOT / "environment" / "toolchains"
INVENTORY = ROOT / "environment" / "node_toolchain_inventory.json"
NODE_VERSIONS = ("12.22.12", "14.21.3", "16.20.2")
YARN_VERSION = "1.22.22"


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "mvscan-f1-environment-freeze/1.0"}
    )
    with urllib.request.urlopen(request, timeout=300) as response, destination.open("xb") as stream:
        shutil.copyfileobj(response, stream, length=1024 * 1024)


def extract_node(version: str) -> dict[str, object]:
    tag = "v" + version
    filename = f"node-{tag}-linux-x64.tar.xz"
    directory = ARCHIVES / tag
    directory.mkdir(parents=True)
    checksums = directory / "SHASUMS256.txt"
    archive = directory / filename
    base_url = f"https://nodejs.org/dist/{tag}/"
    download(base_url + "SHASUMS256.txt", checksums)
    download(base_url + filename, archive)
    expected_rows = {
        row.split()[1]: row.split()[0]
        for row in checksums.read_text(encoding="ascii").splitlines()
        if len(row.split()) == 2
    }
    expected = expected_rows.get(filename)
    actual = sha256_file(archive)
    if expected is None or actual != expected:
        raise RuntimeError(f"Node {version} archive hash mismatch")
    destination = TOOLCHAINS / "node" / version
    if destination.exists():
        raise FileExistsError(destination)
    temporary = destination.with_name("." + destination.name + ".partial")
    temporary.mkdir(parents=True)
    prefix = f"node-{tag}-linux-x64/"
    with tarfile.open(archive, "r:xz") as bundle:
        for member in bundle.getmembers():
            if member.name == prefix.rstrip("/"):
                continue
            if not member.name.startswith(prefix):
                raise RuntimeError("unexpected Node archive prefix")
            relative = member.name[len(prefix):]
            if not relative:
                continue
            member.name = relative
            bundle.extract(member, temporary)
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(temporary, destination)
    node = destination / "bin" / "node"
    npm = destination / "bin" / "npm"
    node_output = subprocess.check_output([node, "--version"], text=True).strip()
    npm_output = subprocess.check_output(
        [node, destination / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js", "--version"],
        text=True,
    ).strip()
    if node_output != tag:
        raise RuntimeError(f"Node {version} executable mismatch")
    digest, file_count, byte_size = tree_digest(destination)
    binaries = []
    for name in ("node", "npm", "npx"):
        path = destination / "bin" / name
        binaries.append({
            "name": name,
            "relative_path": path.relative_to(ROOT).as_posix(),
            "symlink_target": os.readlink(path) if path.is_symlink() else None,
            "sha256": sha256_file(path),
            "byte_size": path.stat().st_size,
        })
    return {
        "version": version,
        "npm_version": npm_output,
        "archive_relative_path": archive.relative_to(ROOT).as_posix(),
        "archive_sha256": actual,
        "checksums_relative_path": checksums.relative_to(ROOT).as_posix(),
        "checksums_sha256": sha256_file(checksums),
        "tree_sha256": digest,
        "file_count": file_count,
        "byte_size": byte_size,
        "binaries": binaries,
    }


def extract_yarn(node_record: dict[str, object]) -> dict[str, object]:
    registry = json.loads(YARN_INDEX.read_text(encoding="utf-8"))
    metadata = registry["versions"][YARN_VERSION]
    directory = ARCHIVES / ("yarn-" + YARN_VERSION)
    directory.mkdir()
    archive = directory / f"yarn-{YARN_VERSION}.tgz"
    download(metadata["dist"]["tarball"], archive)
    integrity = metadata["dist"]["integrity"]
    algorithm, encoded = integrity.split("-", 1)
    if algorithm != "sha512":
        raise RuntimeError("unexpected Yarn integrity algorithm")
    actual_sha512 = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode("ascii")
    if actual_sha512 != encoded:
        raise RuntimeError("Yarn archive integrity mismatch")
    destination = TOOLCHAINS / "yarn" / YARN_VERSION
    temporary = destination.with_name("." + destination.name + ".partial")
    temporary.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            if not member.name.startswith("package/"):
                raise RuntimeError("unexpected Yarn archive prefix")
            relative = member.name[len("package/"):]
            if not relative:
                continue
            member.name = relative
            bundle.extract(member, temporary)
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(temporary, destination)
    node = ROOT / node_record["binaries"][0]["relative_path"]
    output = subprocess.check_output(
        [node, destination / "bin" / "yarn.js", "--version"], text=True
    ).strip()
    if output != YARN_VERSION:
        raise RuntimeError("Yarn version validation failed")
    digest, file_count, byte_size = tree_digest(destination)
    return {
        "version": YARN_VERSION,
        "archive_relative_path": archive.relative_to(ROOT).as_posix(),
        "archive_sha256": sha256_file(archive),
        "archive_integrity": integrity,
        "tree_sha256": digest,
        "file_count": file_count,
        "byte_size": byte_size,
        "entrypoint_relative_path": (destination / "bin" / "yarn.js").relative_to(ROOT).as_posix(),
        "entrypoint_sha256": sha256_file(destination / "bin" / "yarn.js"),
    }


def select_profile(snapshot: dict[str, object]) -> tuple[str | None, str]:
    manager = snapshot["package_manager_family"]
    if manager is None:
        return None, "no JavaScript package manager evidence"
    nvmrc = snapshot.get("nvmrc")
    node_file = snapshot.get("node_version_file")
    exact = nvmrc or node_file
    if exact == "lts/erbium":
        return "node12-yarn1" if manager == "yarn" else "node12-npm6", ".nvmrc lts/erbium"
    if exact == "14":
        return "node14-yarn1" if manager == "yarn" else "node14-npm6", ".nvmrc 14"
    if manager == "npm":
        lock_version = snapshot.get("package_lock_version")
        if lock_version == 1:
            return "node14-npm6", "package-lock v1 compatibility inventory"
        if lock_version == 2:
            return "node16-npm8", "package-lock v2 compatibility inventory"
        return None, "npm lockfile format unresolved"
    if manager == "yarn":
        return "node16-yarn1", "Yarn v1 lockfile compatibility inventory"
    return None, "package manager unsupported by frozen compatibility inventory"


def main() -> int:
    if ARCHIVES.exists() or (TOOLCHAINS / "node").exists() or INVENTORY.exists():
        raise FileExistsError("refusing to overwrite Node toolchain freeze")
    index = json.loads(NODE_INDEX.read_text(encoding="utf-8"))
    index_by_version = {row["version"].removeprefix("v"): row for row in index}
    if any(version not in index_by_version for version in NODE_VERSIONS):
        raise RuntimeError("Node release absent from frozen official index")
    ARCHIVES.mkdir(parents=True)
    records = [extract_node(version) for version in NODE_VERSIONS]
    yarn = extract_yarn(records[-1])
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    selections = []
    unresolved = []
    for snapshot in evidence["snapshots"]:
        profile, basis = select_profile(snapshot)
        row = {
            "snapshot_id": snapshot["snapshot_id"],
            "package_manager_family": snapshot["package_manager_family"],
            "profile": profile,
            "selection_evidence": basis,
        }
        selections.append(row)
        if snapshot["package_manager_family"] is not None and profile is None:
            unresolved.append(snapshot["snapshot_id"])
    profiles = {
        "node12-npm6": {"node": "12.22.12", "npm": next(row["npm_version"] for row in records if row["version"] == "12.22.12")},
        "node12-yarn1": {"node": "12.22.12", "yarn": YARN_VERSION},
        "node14-npm6": {"node": "14.21.3", "npm": next(row["npm_version"] for row in records if row["version"] == "14.21.3")},
        "node14-yarn1": {"node": "14.21.3", "yarn": YARN_VERSION},
        "node16-npm8": {"node": "16.20.2", "npm": next(row["npm_version"] for row in records if row["version"] == "16.20.2")},
        "node16-yarn1": {"node": "16.20.2", "yarn": YARN_VERSION},
    }
    write_json_new(INVENTORY, {
        "schema_version": 1,
        "status": "UNRESOLVED" if unresolved else "COMPLETE",
        "frozen_before_detector_output": True,
        "selection_evidence_order": [
            "packageManager", ".nvmrc_or_node-version", "project_CI", "engines",
            "lockfile_format_and_prefrozen_inventory",
        ],
        "official_node_index_sha256": sha256_file(NODE_INDEX),
        "official_yarn_registry_sha256": sha256_file(YARN_INDEX),
        "node_toolchains": records,
        "yarn_toolchain": yarn,
        "compatibility_profiles": profiles,
        "snapshot_selections": selections,
        "unresolved_snapshot_ids": unresolved,
    })
    print(json.dumps({
        "node_toolchains": len(records),
        "yarn_version": YARN_VERSION,
        "selected_snapshots": sum(row["profile"] is not None for row in selections),
        "unresolved_snapshots": len(unresolved),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
