#!/usr/bin/env python3
"""Record Web3Bugs build-screen blockers without weakening frozen resource rules."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from runners.common import ROOT, write_json_new

POPULATION = ROOT / "benchmarks" / "web3bugs" / "population.csv"
EVIDENCE = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
ATTEMPTS = ROOT / "benchmarks" / "web3bugs" / "build_attempts.csv"
ATTEMPT_ARCHIVE = ROOT / "benchmarks" / "web3bugs" / "build_screen_attempts" / "initial-header-only.csv"
SUMMARY = ROOT / "benchmarks" / "web3bugs" / "build_screen_summary.json"
NODE_INVENTORY = ROOT / "environment" / "node_toolchain_inventory.json"
COMPILER_INVENTORY = ROOT / "environment" / "compiler_inventory.json"
ENVIRONMENT_MANIFEST = ROOT / "environment" / "environment_manifest.json"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FIELDS = [
    "attempt_id", "snapshot_id", "command_evidence_rank", "command_evidence",
    "command", "toolchain_evidence", "toolchain", "started_at",
    "duration_seconds", "timeout_seconds", "exit_code", "terminal_status",
    "stdout_sha256", "stderr_sha256", "source_sha256_before",
    "source_sha256_after", "build_sha256", "prohibited_edit_detected",
    "acceptance_check", "notes",
]


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def main() -> int:
    population = rows(POPULATION)
    if len(population) != 102 or len({row["snapshot_id"] for row in population}) != 102:
        raise RuntimeError("Web3Bugs population identity failure")
    if rows(ATTEMPTS):
        raise FileExistsError("refusing to overwrite Web3Bugs build attempts")
    if ATTEMPT_ARCHIVE.exists() or SUMMARY.exists():
        raise FileExistsError("Web3Bugs build screen already initialized")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    by_id = {row["snapshot_id"]: row for row in evidence["snapshots"]}
    node = json.loads(NODE_INVENTORY.read_text(encoding="utf-8"))
    node_by_id = {row["snapshot_id"]: row for row in node["snapshot_selections"]}
    compiler = json.loads(COMPILER_INVENTORY.read_text(encoding="utf-8"))
    available_solc = {row["version"] for row in compiler["compilers"]}
    environment = json.loads(ENVIRONMENT_MANIFEST.read_text(encoding="utf-8"))
    ATTEMPT_ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    os.replace(ATTEMPTS, ATTEMPT_ARCHIVE)
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    records, counts = [], {}
    for population_row in sorted(population, key=lambda row: int(row["snapshot_id"])):
        snapshot_id = population_row["snapshot_id"]
        item = by_id[snapshot_id]
        command = item["selected_build_command"] or ""
        declarations = sorted({
            version
            for versions in item["compiler_declarations"].values()
            for version in versions
        })
        if any(version not in available_solc for version in declarations):
            raise RuntimeError("selected config compiler absent from frozen inventory")
        node_selection = node_by_id[snapshot_id]
        if command:
            chosen = next(
                row for row in item["build_command_candidates"]
                if row["command"] == command and row["rank"] == item["selected_evidence_rank"]
            )
            terminal = "ENVIRONMENT_UNAVAILABLE"
            acceptance = "BLOCKED_ENVIRONMENT"
            command_evidence = chosen["evidence"]
            notes = (
                "Command and toolchains frozen but no build process ran: the account "
                "cannot enforce the frozen memory/swap cgroup and rootless Docker "
                "uidmap helpers are absent."
            )
        else:
            terminal = "UNRESOLVED_BUILD_COMMAND"
            acceptance = "BLOCKED_BUILD_RECONSTRUCTION"
            lowest = min(
                (candidate["rank"] for candidate in item["build_command_candidates"]),
                default=4,
            )
            if item["selection_status"] == "UNRESOLVED_AMBIGUOUS_BUILD_EVIDENCE":
                alternatives = sorted({
                    row["command"] for row in item["build_command_candidates"]
                    if row["rank"] == lowest
                })
                command_evidence = "ambiguous lowest-rank commands: " + json.dumps(alternatives)
            else:
                command_evidence = (
                    "no permitted rank 1-3 command evidence; direct compilation "
                    "requires source-completeness and pragma analysis not authorized "
                    "by the execution safety gate"
                )
            notes = "No arbitrary build command or tool version was tried."
        counts[terminal] = counts.get(terminal, 0) + 1
        records.append({
            "attempt_id": f"web3bugs-{snapshot_id}-build-screen-001",
            "snapshot_id": snapshot_id,
            "command_evidence_rank": str(item["selected_evidence_rank"] or ""),
            "command_evidence": command_evidence,
            "command": command,
            "toolchain_evidence": json.dumps({
                "node": node_selection["selection_evidence"],
                "compiler": "exact native build configuration" if declarations else "unresolved",
            }, sort_keys=True, separators=(",", ":")),
            "toolchain": json.dumps({
                "oci_digest": environment["immutable_oci_digest"],
                "node_profile": node_selection["profile"],
                "solc_versions": declarations,
            }, sort_keys=True, separators=(",", ":")),
            "started_at": timestamp,
            "duration_seconds": "0",
            "timeout_seconds": "900",
            "exit_code": "",
            "terminal_status": terminal,
            "stdout_sha256": EMPTY_SHA256,
            "stderr_sha256": EMPTY_SHA256,
            "source_sha256_before": population_row["snapshot_sha256"],
            "source_sha256_after": population_row["snapshot_sha256"],
            "build_sha256": "",
            "prohibited_edit_detected": "false",
            "acceptance_check": acceptance,
            "notes": notes,
        })
    with ATTEMPTS.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    summary = {
        "schema_version": 1,
        "population_rows": 102,
        "screened_rows": 102,
        "accepted_builds": 0,
        "terminal_status_counts": counts,
        "resolved_commands": sum(bool(row["command"]) for row in records),
        "prohibited_edits": 0,
        "f1_statuses": ["BLOCKED_BUILD_RECONSTRUCTION", "BLOCKED_ENVIRONMENT"],
    }
    write_json_new(SUMMARY, summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
