#!/usr/bin/env python3
"""Validate completed independent reviews and materialize final adjudicated labels."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

WEB3_LABELS = {"TP_MVSI", "VALID_OTHER_ISU", "NONBUG", "INSUFFICIENT_EVIDENCE"}
ISU_LABELS = {"MV_SI", "SV_SI", "ISU_OTHER", "OTHER", "INSUFFICIENT_EVIDENCE"}
BOOL = {"true", "false"}
COMPARE = ("C1", "C2", "C3", "C4", "C5")


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def keyed(path: Path, key: str) -> dict[str, dict[str, str]]:
    values = rows(path)
    result = {row.get(key, ""): row for row in values}
    if not values or "" in result or len(result) != len(values):
        raise ValueError(f"{path}: missing or duplicate {key}")
    return result


def validate_decision(row: dict[str, str], label_field: str, labels: set[str], context: str) -> list[str]:
    errors = []
    if row.get(label_field) not in labels:
        errors.append(f"{context}: invalid or blank {label_field}")
    if any(row.get(field) not in BOOL for field in COMPARE):
        errors.append(f"{context}: C1-C5 must be lowercase booleans")
    if row.get("confidence") not in {"high", "medium", "low"}:
        errors.append(f"{context}: confidence must be high, medium, or low")
    if not row.get("evidence_notes", "").strip():
        errors.append(f"{context}: evidence_notes is required")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("handoff", type=Path)
    parser.add_argument("isu_adjudication", type=Path)
    parser.add_argument("web3bugs_adjudication", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"output exists: {args.output}")
    errors = []
    primary = keyed(args.handoff / "web3bugs_primary.csv", "global_candidate_id")
    agreement = keyed(args.handoff / "web3bugs_agreement.csv", "global_candidate_id")
    isu1 = keyed(args.handoff / "isu_reviewer_1.csv", "oracle_row_id")
    isu2 = keyed(args.handoff / "isu_reviewer_2.csv", "oracle_row_id")
    if set(agreement) - set(primary): errors.append("agreement sheet is not a primary-sheet subset")
    if set(isu1) != set(isu2): errors.append("ISU reviewer populations differ")
    for key, row in primary.items(): errors += validate_decision(row, "label", WEB3_LABELS, f"Web3Bugs primary {key}")
    for key, row in agreement.items(): errors += validate_decision(row, "label", WEB3_LABELS, f"Web3Bugs agreement {key}")
    for key, row in isu1.items(): errors += validate_decision(row, "semantic_class", ISU_LABELS, f"ISU reviewer 1 {key}")
    for key, row in isu2.items(): errors += validate_decision(row, "semantic_class", ISU_LABELS, f"ISU reviewer 2 {key}")
    web_disagreements = {key for key, second in agreement.items()
                         if any(primary[key].get(field) != second.get(field) for field in ("label",) + COMPARE)}
    isu_disagreements = {key for key in isu1
                         if any(isu1[key].get(field) != isu2[key].get(field) for field in ("semantic_class",) + COMPARE)}
    web_adj = keyed(args.web3bugs_adjudication, "global_candidate_id") if args.web3bugs_adjudication.is_file() else {}
    isu_adj = keyed(args.isu_adjudication, "oracle_row_id") if args.isu_adjudication.is_file() else {}
    if set(web_adj) != web_disagreements: errors.append("Web3Bugs adjudication does not exactly cover disagreements")
    if set(isu_adj) != isu_disagreements: errors.append("ISU adjudication does not exactly cover disagreements")
    for key, row in web_adj.items():
        if row.get("final_label") not in WEB3_LABELS or not row.get("rationale", "").strip(): errors.append(f"invalid Web3Bugs adjudication: {key}")
    for key, row in isu_adj.items():
        if row.get("adjudicated_class") not in ISU_LABELS or not row.get("rationale", "").strip(): errors.append(f"invalid ISU adjudication: {key}")
    if errors:
        print(json.dumps({"status": "INVALID", "error_count": len(errors), "errors": errors[:200]}, sort_keys=True)); return 1
    args.output.mkdir(parents=True)
    final_web = [{"global_candidate_id": key, "final_label": web_adj[key]["final_label"] if key in web_adj else row["label"]}
                 for key, row in sorted(primary.items())]
    final_isu = [{"oracle_row_id": key, "adjudicated_class": isu_adj[key]["adjudicated_class"] if key in isu_adj else row["semantic_class"]}
                 for key, row in sorted(isu1.items())]
    for name, fields, values in (("web3bugs_final.csv", ["global_candidate_id", "final_label"], final_web),
                                 ("isu_final.csv", ["oracle_row_id", "adjudicated_class"], final_isu)):
        with (args.output / name).open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(values)
    print(json.dumps({"status": "COMPLETE", "web3bugs": len(final_web), "isu": len(final_isu),
                      "web3bugs_disagreements": len(web_disagreements), "isu_disagreements": len(isu_disagreements)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
