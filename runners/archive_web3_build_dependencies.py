#!/usr/bin/env python3
"""Losslessly archive expanded per-attempt dependency trees, then reclaim their copies."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from runners.common import ROOT, canonical_bytes
from runners.best_effort_builds import ATTEMPTS


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def directory_stats(paths: list[Path]) -> tuple[int, int]:
    count = 0
    size = 0
    for root in paths:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                count += 1
                size += path.stat().st_size
    return count, size


def archive_attempt(attempt: Path) -> dict[str, object] | None:
    if not (attempt / "attempt_manifest.json").is_file():
        return None
    archive = attempt / "expanded_dependencies.tar.zst"
    manifest_path = attempt / "expanded_dependencies_archive_manifest.json"
    if manifest_path.is_file():
        return None
    candidates = []
    workspace = attempt / "workspace"
    if workspace.is_dir():
        for path in workspace.rglob("node_modules"):
            if path.is_dir() and not any(parent.name == "node_modules" for parent in path.parents):
                candidates.append(path)
    for relative in ("npm-cache", "yarn-cache", "home/.cache", "home/.solcx", "xdg-cache"):
        path = attempt / relative
        if path.is_dir():
            candidates.append(path)
    candidates = sorted(set(candidates), key=lambda path: path.relative_to(attempt).as_posix())
    if not candidates:
        return None
    file_count, byte_size = directory_stats(candidates)
    relative = [path.relative_to(attempt).as_posix() for path in candidates]
    command = ["tar", "--zstd", "-cf", str(archive), "-C", str(attempt), *relative]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=3600, check=False)
    if result.returncode:
        if archive.exists():
            archive.unlink()
        raise RuntimeError(f"archive failed for {attempt}: {result.stderr.decode('utf-8', 'replace')[-1000:]}")
    verification = subprocess.run(
        ["tar", "--zstd", "-tf", str(archive)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=900,
        check=False,
    )
    if verification.returncode:
        raise RuntimeError(f"archive verification failed for {attempt}")
    manifest = {
        "schema_version": 1,
        "attempt_id": attempt.name,
        "archive_path": archive.relative_to(ROOT).as_posix(),
        "archive_sha256": digest(archive),
        "archive_byte_size": archive.stat().st_size,
        "expanded_file_count": file_count,
        "expanded_byte_size": byte_size,
        "archived_paths": relative,
        "restore_command": f"tar --zstd -xf {archive.name} -C {attempt.relative_to(ROOT).as_posix()}",
    }
    manifest_path.write_bytes(canonical_bytes(manifest))
    for path in sorted(candidates, key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            shutil.rmtree(path)
    return manifest


def main() -> int:
    archived = 0
    expanded = 0
    compressed = 0
    for attempt in sorted(ATTEMPTS.glob("*/*")):
        result = archive_attempt(attempt)
        if not result:
            continue
        archived += 1
        expanded += int(result["expanded_byte_size"])
        compressed += int(result["archive_byte_size"])
        print(json.dumps({
            "attempt_id": result["attempt_id"],
            "expanded_bytes": result["expanded_byte_size"],
            "archive_bytes": result["archive_byte_size"],
        }, sort_keys=True), flush=True)
    print(json.dumps({"attempts_archived": archived, "expanded_bytes": expanded, "archive_bytes": compressed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
