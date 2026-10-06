#!/usr/bin/env python3
"""Recover unavailable ISU revisions only from mirrors containing the exact Git object."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import subprocess
import uuid

from runners.common import ROOT

ACQUISITION = ROOT / "benchmarks" / "isu" / "source_acquisition_best_effort.csv"
MAPPING = ROOT / "benchmarks" / "isu" / "source_acquisition_row_mapping.csv"
SOURCES = ROOT / "benchmarks" / "isu" / "sources"
LOGS = ROOT / "benchmarks" / "isu" / "source_acquisition_logs"
MIRRORS = {
    "51822de69e2919a4a935": "https://github.com/ShehabKhan96/tapioca-bar-audit.git",
}


def main() -> int:
    with ACQUISITION.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    # Re-read fields without relying on the exhausted reader.
    with ACQUISITION.open(newline="", encoding="utf-8") as stream:
        fields = list(csv.DictReader(stream).fieldnames or [])
    for field in ("acquisition_repository", "acquisition_method"):
        if field not in fields:
            fields.append(field)
    recovered = []
    for row in rows:
        mirror = MIRRORS.get(row["source_id"])
        if not mirror or row["status"].startswith("ACQUIRED"):
            continue
        revision = row["requested_revision"]
        target = ROOT / row["source_path"]
        temporary = SOURCES / f".{row['source_id']}.mirror-{uuid.uuid4().hex}"
        temporary.mkdir(parents=True, exist_ok=False)
        log = LOGS / row["source_id"] / "exact_mirror_recovery.log"
        with log.open("wb") as output:
            commands = (
                ["git", "init"], ["git", "remote", "add", "origin", mirror],
                ["git", "fetch", "--depth", "1", "origin", revision],
                ["git", "checkout", "--detach", "FETCH_HEAD"],
            )
            for command in commands:
                result = subprocess.run(command, cwd=temporary, stdout=output, stderr=output, timeout=900, check=False)
                if result.returncode:
                    raise RuntimeError(f"exact mirror recovery failed: {' '.join(command)}")
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=temporary, text=True).strip()
        if head != revision:
            raise RuntimeError(f"mirror HEAD {head} != requested {revision}")
        submodules = subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
            cwd=temporary, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, check=False,
        )
        with (LOGS / row["source_id"] / "exact_mirror_submodules.log").open("wb") as output:
            output.write(submodules.stdout)
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=temporary, text=True).strip()
        os.replace(temporary, target)
        row.update({
            "checkout_revision": head, "git_tree": tree,
            "status": "ACQUIRED_EXACT_MIRROR",
            "submodule_status": "SUCCESS" if submodules.returncode == 0 else f"FAILURE_EXIT_{submodules.returncode}",
            "error": "", "acquisition_repository": mirror,
            "acquisition_method": "exact commit object fetched from public mirror after evidence repository became unavailable",
        })
        recovered.append(row["source_id"])
    with ACQUISITION.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    by_source = {row["source_id"]: row for row in rows}
    with MAPPING.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        mapping_fields = list(reader.fieldnames or [])
        mapping = list(reader)
    for row in mapping:
        acquired = by_source.get(row["source_id"])
        if acquired:
            row["acquisition_status"] = acquired["status"]
    with MAPPING.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=mapping_fields, lineterminator="\n")
        writer.writeheader(); writer.writerows(mapping)
    print(json.dumps({"recovered_exact_mirrors": recovered}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
