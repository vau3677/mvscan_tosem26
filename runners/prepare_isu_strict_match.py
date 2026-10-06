#!/usr/bin/env python3
"""Prepare strict B0-match packets after ISU semantic adjudication."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from runners.artifact_storage import read_json
from runners.common import ROOT, canonical_bytes

CLASSES = {"MV_SI", "NON_MVSI", "INSUFFICIENT_EVIDENCE"}
FIELDS = ["oracle_row_id", "accepted_build", "b0_run_status", "packet", "candidate_reference",
          "semantic_match", "over_approximation", "nonmatch_reason", "notes"]


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def compact_candidate(candidate: dict[str, Any], unit_id: Any) -> dict[str, Any]:
    return {"compilation_unit_id": unit_id, "candidate_id": candidate.get("candidate_id"),
            "relation": candidate.get("relation"), "writer_owner": candidate.get("writer_owner"),
            "writer_block": candidate.get("writer_block"), "written_members": candidate.get("written_members"),
            "potentially_stale_members": candidate.get("potentially_stale_members"),
            "supporting_origin_sites": candidate.get("supporting_origin_sites"),
            "reader_witnesses": candidate.get("reader_witnesses")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("adjudication", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"output exists: {args.output}")
    adjudication = csv_rows(args.adjudication)
    decisions = {}
    for row in adjudication:
        oracle_id, semantic_class = row.get("oracle_row_id", ""), row.get("adjudicated_class", "")
        if not oracle_id or semantic_class not in CLASSES:
            raise ValueError(f"missing/invalid adjudication: {oracle_id}: {semantic_class}")
        if oracle_id in decisions:
            raise ValueError(f"duplicate adjudication: {oracle_id}")
        decisions[oracle_id] = semantic_class
    population = {row["oracle_row_id"]: row for row in csv_rows(ROOT / "benchmarks/isu/oracle_population.csv")}
    if set(decisions) != set(population):
        raise ValueError("adjudication must contain every oracle row exactly once")
    mapping = {row["oracle_row_id"]: row for row in csv_rows(ROOT / "benchmarks/isu/execution_subject_map.csv")}
    coverage = {row["oracle_row_id"]: row for row in csv_rows(ROOT / "benchmarks/isu/oracle_build_coverage.csv")}
    runs = {}
    for path in (ROOT / "runs").glob("*/run_manifest.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if (manifest.get("dataset"), manifest.get("configuration"), manifest.get("python_hash_seed")) == ("isu", "B0", 0):
            runs[str(manifest["subject"])] = (path, manifest)
    args.output.mkdir(parents=True)
    packet_dir = args.output / "packets"
    packet_dir.mkdir()
    output_rows = []
    for oracle_id in sorted(key for key, value in decisions.items() if value == "MV_SI"):
        subject = mapping.get(oracle_id, {}).get("execution_subject_id", "")
        run = runs.get(subject)
        status = run[1].get("terminal_status", "MISSING") if run else "NOT_RUN"
        candidates = []
        if run and status == "SUCCESS":
            path, manifest = run
            document = read_json(path.parent / manifest["detector_json"])
            for unit in document.get("compilation_units", []):
                candidates.extend(compact_candidate(candidate, unit.get("unit_id")) for candidate in unit.get("candidates", []))
        packet = {"schema_version": 1, "oracle_row_id": oracle_id,
                  "report_identity": population[oracle_id]["report_identity"],
                  "report_url": population[oracle_id]["report_url"],
                  "execution_subject_id": subject or None, "b0_run_status": status,
                  "strict_match_requirements": ["semantic relation core", "desynchronizing writer",
                      "correct written and omitted roles", "required persistent read and sink",
                      "compatible execution ordering"], "b0_candidates": candidates}
        packet_path = packet_dir / f"{oracle_id}.json"
        packet_path.write_bytes(canonical_bytes(packet) + b"\n")
        output_rows.append({"oracle_row_id": oracle_id,
                            "accepted_build": coverage.get(oracle_id, {}).get("build_coverage") == "COMPILED",
                            "b0_run_status": status, "packet": f"packets/{packet_path.name}"})
    with (args.output / "review.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(output_rows)
    print(json.dumps({"adjudicated_mvsi": len(output_rows),
                      "successful_b0": sum(row["b0_run_status"] == "SUCCESS" for row in output_rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
