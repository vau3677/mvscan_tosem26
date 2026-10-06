#!/usr/bin/env python3
"""Validate that the generated reviewer handoff is complete, blind, and reproducible."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from runners.common import ROOT
from runners.select_samples import select_configurations


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def has_key(value: object, forbidden: set[str]) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() in forbidden or has_key(item, forbidden) for key, item in value.items())
    if isinstance(value, list):
        return any(has_key(item, forbidden) for item in value)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("handoff", type=Path)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    errors = []
    handoff = args.handoff
    manifest = json.loads((handoff / "MANIFEST.json").read_text(encoding="utf-8"))
    for record in manifest["files"]:
        path = handoff / record["path"]
        if not path.is_file():
            errors.append(f"missing manifest file: {record['path']}")
        elif path.stat().st_size != record["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            errors.append(f"manifest mismatch: {record['path']}")
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    by_id = {bucket["global_candidate_id"]: bucket for bucket in inventory["buckets"]}
    populations = {name: [] for name in inventory["configurations"]}
    for bucket in inventory["buckets"]:
        for name in bucket["configurations"]:
            populations[name].append(bucket["global_candidate_id"])
    expected = select_configurations(populations)
    primary = rows(handoff / "web3bugs_primary.csv")
    agreement = rows(handoff / "web3bugs_agreement.csv")
    primary_ids = [row["global_candidate_id"] for row in primary]
    agreement_ids = [row["global_candidate_id"] for row in agreement]
    if set(primary_ids) != set(expected["unique_primary"]) or len(primary_ids) != len(set(primary_ids)):
        errors.append("Web3Bugs primary sheet differs from deterministic selection")
    if set(agreement_ids) != set(expected["agreement"]) or len(agreement_ids) != len(set(agreement_ids)):
        errors.append("Web3Bugs agreement sheet differs from deterministic selection")
    review_fields = {"label", "nonbug_primary_cause", "C1", "C2", "C3", "C4", "C5", "confidence", "evidence_notes"}
    for row in primary + agreement:
        if any(row.get(field, "").strip() for field in review_fields):
            errors.append(f"pre-filled Web3Bugs decision: {row.get('review_id')}")
        packet_path = handoff / row["packet"]
        if not packet_path.is_file():
            errors.append(f"missing Web3Bugs packet: {row['packet']}")
            continue
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        if any(excerpt.get("status") != "AVAILABLE" for excerpt in packet.get("source_excerpts", [])):
            errors.append(f"unavailable Web3Bugs excerpt: {row['review_id']}")
        if has_key(packet, {"configuration", "configurations", "ablation"}):
            errors.append(f"configuration leakage in packet: {row['review_id']}")
        if row["global_candidate_id"] not in by_id:
            errors.append(f"unknown structural bucket: {row['global_candidate_id']}")
    population_ids = {row["oracle_row_id"] for row in rows(ROOT / "benchmarks/isu/oracle_population.csv")}
    expected_isu = len(population_ids)
    coverage = {row["oracle_row_id"]: row["build_coverage"] for row in rows(ROOT / "benchmarks/isu/oracle_build_coverage.csv")}
    traceability_path = handoff / "known_findings/TRACEABILITY.json"
    if not traceability_path.is_file():
        errors.append("missing known-finding traceability manifest")
        traceability = {}
    else:
        trace = json.loads(traceability_path.read_text(encoding="utf-8"))
        traceability = {item["oracle_row_id"]: item for item in trace.get("cards", [])}
        if set(traceability) != population_ids or len(trace.get("cards", [])) != expected_isu:
            errors.append(f"known-finding cards do not cover all {expected_isu} findings exactly once")
    isu_sheets = [rows(handoff / f"isu_reviewer_{number}.csv") for number in (1, 2)]
    for number, sheet in enumerate(isu_sheets, 1):
        ids = [row["oracle_row_id"] for row in sheet]
        if len(ids) != expected_isu or set(ids) != population_ids or len(ids) != len(set(ids)):
            errors.append(f"ISU reviewer {number} does not cover all {expected_isu} findings exactly once")
        for row in sheet:
            if any(row.get(field, "").strip() for field in {"is_mvsi", "correction_note"}):
                errors.append(f"pre-filled ISU decision: reviewer {number}: {row.get('review_id')}")
            card_path = handoff / row["known_finding"]
            if not card_path.is_file():
                errors.append(f"missing known-finding card: {row['known_finding']}")
            item = traceability.get(row["oracle_row_id"], {})
            if item.get("card") and row["known_finding"] != f"known_findings/{item['card']}":
                errors.append(f"known-finding card mismatch: {row['oracle_row_id']}")
            packet_path = handoff / "known_findings" / item.get("source_packet", "")
            if not packet_path.is_file():
                errors.append(f"missing ISU source packet: {row['oracle_row_id']}")
                continue
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            grounded = any(excerpt.get("status") == "AVAILABLE" for excerpt in packet.get("source_excerpts", []))
            if (coverage[row["oracle_row_id"]] == "COMPILED") != grounded:
                errors.append(f"ISU source-grounding/build mismatch: {row['oracle_row_id']}")
            if "b0_candidates" in packet:
                errors.append(f"detector leakage in initial ISU packet: {row['oracle_row_id']}")
    result = {"status": "READY_FOR_HUMAN_REVIEW" if not errors else "INVALID",
              "errors": errors, "web3bugs_primary": len(primary), "web3bugs_agreement": len(agreement),
              "isu_per_reviewer": [len(sheet) for sheet in isu_sheets]}
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
