#!/usr/bin/env python3
"""Derive immutable best-effort build coverage tables from preserved attempts."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] if "runners" in Path(__file__).parts else Path.cwd()


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def integer(value):
    try:
        return int(value or 0)
    except ValueError:
        return 0


web3 = ROOT / "benchmarks" / "web3bugs"
isu = ROOT / "benchmarks" / "isu"

# Web3Bugs: one row for every frozen population snapshot.
web3_attempts = read_csv(web3 / "best_effort_build_attempts.csv")
web3_by_snapshot = defaultdict(list)
for row in web3_attempts:
    web3_by_snapshot[row["snapshot_id"]].append(row)
incompatible = {
    row["snapshot_id"]: row
    for row in read_csv(web3 / "best_effort_direct_solc_unresolved.csv")
}
web3_rows = []
for population in sorted(read_csv(web3 / "population.csv"), key=lambda row: int(row["snapshot_id"])):
    snapshot = population["snapshot_id"]
    attempts = web3_by_snapshot[snapshot]
    successes = [row for row in attempts if row["terminal_status"] == "SUCCESS"]
    immutable = [row for row in attempts if integer(row["source_mutations"]) == 0]
    max_immutable_artifacts = max((integer(row["artifact_files"]) for row in immutable), default=0)
    max_any_artifacts = max((integer(row["artifact_files"]) for row in attempts), default=0)
    if successes:
        status = "SUCCESS"
        best = max(successes, key=lambda row: integer(row["artifact_files"]))
        reason = "at least one no-edit build completed with compiler artifacts"
    elif snapshot in incompatible:
        status = "EXPLICIT_NO_COMPATIBLE_COMPILER"
        best = None
        reason = incompatible[snapshot]["reason"]
    elif max_immutable_artifacts:
        status = "PARTIAL_COMPILE_POST_FAILURE"
        best = max(immutable, key=lambda row: integer(row["artifact_files"]))
        reason = "no accepted full build; an immutable attempt emitted partial artifacts before failure"
    else:
        status = "ATTEMPTED_FAILED"
        best = attempts[-1] if attempts else None
        reason = "all best-effort no-edit build attempts failed"
    web3_rows.append({
        "snapshot_id": snapshot,
        "status": status,
        "attempt_count": len(attempts),
        "successful_attempt_count": len(successes),
        "prohibited_edit_attempt_count": sum(row["terminal_status"] == "PROHIBITED_EDIT" for row in attempts),
        "max_immutable_artifact_files": max_immutable_artifacts,
        "max_any_attempt_artifact_files": max_any_artifacts,
        "best_manifest_path": best["manifest_path"] if best else "",
        "reason": reason,
    })
write_csv(
    web3 / "best_effort_build_summary.csv",
    list(web3_rows[0]),
    web3_rows,
)

# ISU: one row for every unique exact repository/revision identity.
acquisitions = read_csv(isu / "source_acquisition_best_effort.csv")
isu_attempts = read_csv(isu / "best_effort_build_attempts.csv")
isu_by_source = defaultdict(list)
for row in isu_attempts:
    isu_by_source[row["source_id"]].append(row)
selected = defaultdict(set)
for row in read_csv(isu / "best_effort_selected_projects.csv"):
    selected[row["source_id"]].add(row["project_root"])

isu_rows = []
compiled_sources = set()
for source in sorted(acquisitions, key=lambda row: row["source_id"]):
    source_id = source["source_id"]
    attempts = isu_by_source[source_id]
    successes = [row for row in attempts if row["terminal_status"] == "SUCCESS"]
    success_roots = {row["project_root"] for row in successes}
    selected_roots = selected[source_id]
    if not source["status"].startswith("ACQUIRED"):
        status = "ACQUISITION_FAILURE"
    elif successes and selected_roots and selected_roots.issubset(success_roots):
        status = "ALL_SELECTED_PROJECTS_SUCCESS"
        compiled_sources.add(source_id)
    elif successes and selected_roots:
        status = "PARTIAL_PROJECT_SUCCESS"
        compiled_sources.add(source_id)
    elif successes:
        status = "SUCCESS_FALLBACK"
        compiled_sources.add(source_id)
    elif attempts:
        status = "ATTEMPTED_FAILED"
    else:
        status = "ACQUIRED_NOT_ATTEMPTED"
    best = max(successes or attempts, key=lambda row: integer(row["artifact_files"])) if attempts else None
    isu_rows.append({
        "source_id": source_id,
        "repository": source["repository"],
        "requested_revision": source["requested_revision"],
        "acquisition_status": source["status"],
        "build_status": status,
        "selected_project_count": len(selected_roots),
        "successful_selected_project_count": len(selected_roots & success_roots),
        "attempt_count": len(attempts),
        "successful_attempt_count": len(successes),
        "prohibited_edit_attempt_count": sum(row["terminal_status"] == "PROHIBITED_EDIT" for row in attempts),
        "max_immutable_artifact_files": max((integer(row["artifact_files"]) for row in attempts if integer(row["source_mutations"]) == 0), default=0),
        "best_manifest_path": best["manifest_path"] if best else "",
        "acquisition_error": source["error"],
    })
write_csv(isu / "best_effort_build_summary.csv", list(isu_rows[0]), isu_rows)

# ISU: project repository build status back onto all 116 frozen oracle rows.
mapping = {row["oracle_row_id"]: row for row in read_csv(isu / "source_acquisition_row_mapping.csv")}
resolution = {row["oracle_row_id"]: row for row in read_csv(isu / "source_resolution.csv")}
oracle_rows = []
for oracle in read_csv(isu / "oracle_population.csv"):
    oracle_id = oracle["oracle_row_id"]
    resolved = resolution[oracle_id]
    mapped = mapping.get(oracle_id)
    if not resolved["resolution_status"].startswith("RESOLVED"):
        coverage = "UNRESOLVED_EXACT_REVISION"
        source_id = ""
        repository = resolved["source_repository"]
        revision = resolved["vulnerable_revision"]
    elif not mapped or not mapped["source_id"]:
        coverage = "RESOLUTION_MAPPING_MISSING"
        source_id = ""
        repository = resolved["source_repository"]
        revision = resolved["vulnerable_revision"]
    else:
        source_id = mapped["source_id"]
        repository = mapped["repository"]
        revision = mapped["vulnerable_revision"]
        if not mapped["acquisition_status"].startswith("ACQUIRED"):
            coverage = "ACQUISITION_FAILURE"
        elif source_id in compiled_sources:
            coverage = "COMPILED"
        elif isu_by_source[source_id]:
            coverage = "ATTEMPTED_FAILED"
        else:
            coverage = "ACQUIRED_NOT_ATTEMPTED"
    oracle_rows.append({
        "oracle_row_id": oracle_id,
        "report_identity": oracle["report_identity"],
        "resolution_status": resolved["resolution_status"],
        "source_id": source_id,
        "repository": repository,
        "vulnerable_revision": revision,
        "build_coverage": coverage,
    })
write_csv(isu / "oracle_build_coverage.csv", list(oracle_rows[0]), oracle_rows)

summary = {
    "schema_version": 1,
    "policy": "best-effort exact-revision no-edit builds; SUCCESS_NO_ARTIFACTS and PROHIBITED_EDIT are not compiled successes",
    "web3bugs": {
        "population_snapshots": len(web3_rows),
        "snapshots_with_accepted_compilation": sum(row["status"] == "SUCCESS" for row in web3_rows),
        "status_counts": dict(sorted(Counter(row["status"] for row in web3_rows).items())),
        "attempt_count": len(web3_attempts),
        "prohibited_edit_attempt_count": sum(row["terminal_status"] == "PROHIBITED_EDIT" for row in web3_attempts),
    },
    "isu": {
        "oracle_findings": len(oracle_rows),
        "exact_resolved_findings": sum(row["build_coverage"] != "UNRESOLVED_EXACT_REVISION" for row in oracle_rows),
        "unique_exact_repository_revisions": len(isu_rows),
        "acquired_exact_repository_revisions": sum(row["acquisition_status"].startswith("ACQUIRED") for row in isu_rows),
        "repository_revisions_with_accepted_compilation": len(compiled_sources),
        "repository_status_counts": dict(sorted(Counter(row["build_status"] for row in isu_rows).items())),
        "oracle_build_coverage_counts": dict(sorted(Counter(row["build_coverage"] for row in oracle_rows).items())),
        "attempt_count": len(isu_attempts),
        "prohibited_edit_attempt_count": sum(row["terminal_status"] == "PROHIBITED_EDIT" for row in isu_attempts),
    },
}
with (ROOT / "benchmarks" / "build_best_effort_summary.json").open("w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(json.dumps(summary, indent=2, sort_keys=True))
