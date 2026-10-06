#!/usr/bin/env python3
"""Acquire exact ISU source revisions resolved from explicit report evidence."""

from __future__ import annotations

import concurrent.futures
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

from runners.common import ROOT, canonical_bytes

RESOLUTION = ROOT / "benchmarks" / "isu" / "source_resolution.csv"
SOURCES = ROOT / "benchmarks" / "isu" / "sources"
LOGS = ROOT / "benchmarks" / "isu" / "source_acquisition_logs"
OUTPUT = ROOT / "benchmarks" / "isu" / "source_acquisition_best_effort.csv"
MAPPING = ROOT / "benchmarks" / "isu" / "source_acquisition_row_mapping.csv"


def source_id(repository: str, revision: str) -> str:
    return hashlib.sha256(f"{repository}@{revision}".encode("utf-8")).hexdigest()[:20]


def run(command: list[str], cwd: Path, stdout, stderr) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, timeout=900, check=False)


def acquire(item: tuple[str, str]) -> dict[str, str]:
    repository, revision = item
    identifier = source_id(repository, revision)
    target = SOURCES / identifier
    log_dir = LOGS / identifier
    log_dir.mkdir(parents=True, exist_ok=True)
    status = ""
    error = ""
    submodule_status = "NOT_RUN"
    try:
        if target.is_dir():
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
            if head != revision:
                raise RuntimeError(f"existing checkout HEAD {head} != {revision}")
            status = "REUSED_VERIFIED"
        else:
            SOURCES.mkdir(parents=True, exist_ok=True)
            temporary = SOURCES / f".{identifier}.tmp-{uuid.uuid4().hex}"
            temporary.mkdir(parents=True, exist_ok=False)
            with (log_dir / "git.stdout.log").open("wb") as stdout, (log_dir / "git.stderr.log").open("wb") as stderr:
                commands = (
                    ["git", "init"],
                    ["git", "remote", "add", "origin", repository],
                    ["git", "fetch", "--depth", "1", "origin", revision],
                    ["git", "checkout", "--detach", "FETCH_HEAD"],
                )
                for command in commands:
                    result = run(command, temporary, stdout, stderr)
                    if result.returncode:
                        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=temporary, text=True).strip()
            if head != revision:
                raise RuntimeError(f"fetched HEAD {head} != {revision}")
            os.replace(temporary, target)
            status = "ACQUIRED"
        with (log_dir / "submodules.stdout.log").open("wb") as stdout, (log_dir / "submodules.stderr.log").open("wb") as stderr:
            result = run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1"], target, stdout, stderr)
        submodule_status = "SUCCESS" if result.returncode == 0 else f"FAILURE_EXIT_{result.returncode}"
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=target, text=True).strip()
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    except Exception as exc:
        status = "ACQUISITION_FAILURE"
        error = f"{type(exc).__name__}: {exc}"
        tree = ""
        commit = ""
    return {
        "source_id": identifier,
        "repository": repository,
        "requested_revision": revision,
        "checkout_revision": commit,
        "git_tree": tree,
        "source_path": target.relative_to(ROOT).as_posix(),
        "status": status,
        "submodule_status": submodule_status,
        "error": error,
    }


def main() -> int:
    rows = list(csv.DictReader(RESOLUTION.open(newline="", encoding="utf-8")))
    resolved = [
        row for row in rows
        if row["resolution_status"].startswith("RESOLVED_")
        and len(row["vulnerable_revision"]) == 40
    ]
    unique = sorted(set((row["source_repository"], row["vulnerable_revision"]) for row in resolved))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(acquire, unique))
    results.sort(key=lambda row: row["source_id"])
    fields = ("source_id", "repository", "requested_revision", "checkout_revision", "git_tree", "source_path", "status", "submodule_status", "error")
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader(); writer.writerows(results)
    by_key = {(row["repository"], row["requested_revision"]): row for row in results}
    mapping_fields = ("oracle_row_id", "source_id", "repository", "vulnerable_revision", "source_path", "acquisition_status")
    with MAPPING.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=mapping_fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            acquired = by_key.get((row["source_repository"], row["vulnerable_revision"]))
            writer.writerow({
                "oracle_row_id": row["oracle_row_id"],
                "source_id": acquired["source_id"] if acquired else "",
                "repository": row["source_repository"],
                "vulnerable_revision": row["vulnerable_revision"],
                "source_path": acquired["source_path"] if acquired else "",
                "acquisition_status": acquired["status"] if acquired else row["resolution_status"],
            })
    counts = {}
    for row in results:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print(json.dumps({"resolved_rows": len(resolved), "unique_sources": len(unique), "status_counts": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
