#!/usr/bin/env python3
"""Validate completed independent reviews and materialize final adjudicated labels."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

WEB3_LABELS = {"TP_MVSI", "VALID_OTHER_ISU", "NONBUG", "INSUFFICIENT_EVIDENCE"}
ISU_DECISIONS = {"Y", "N", "U"}
BOOL = {"Y", "N"}
COMPARE = ("C1", "C2", "C3", "C4", "C5")


def normalized_criteria(row: dict[str, str]) -> tuple[str, ...]:
    """Blank means Y, but only on a row explicitly marked complete."""
    return tuple(row.get(field, "").strip().upper() or "Y" for field in COMPARE)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def keyed(path: Path, key: str) -> dict[str, dict[str, str]]:
    values = rows(path)
    result = {row.get(key, ""): row for row in values}
    if not values or "" in result or len(result) != len(values):
        raise ValueError(f"{path}: missing or duplicate {key}")
    return result


def validate_web3_decision(row: dict[str, str], context: str) -> list[str]:
    errors = []
    if row.get("review_complete", "").strip().upper() != "Y":
        errors.append(f"{context}: review_complete must be Y")
    criteria = normalized_criteria(row)
    if any(value not in BOOL for value in criteria):
        errors.append(f"{context}: C1-C5 must be blank, Y, or N")
    all_pass = all(value == "Y" for value in criteria)
    label = row.get("label", "").strip() or ("TP_MVSI" if all_pass else "")
    if label not in WEB3_LABELS:
        errors.append(f"{context}: label is required only when a criterion fails")
    if all_pass and label != "TP_MVSI":
        errors.append(f"{context}: all passing criteria mechanically imply TP_MVSI")
    if not row.get("evidence_notes", "").strip():
        errors.append(f"{context}: evidence_notes is required")
    return errors


def validate_isu_decision(row: dict[str, str], context: str) -> list[str]:
    errors = []
    if row.get("review_complete", "").strip().upper() != "Y":
        errors.append(f"{context}: review_complete must be Y")
    criteria = tuple(row.get(field, "").strip().upper() for field in COMPARE)
    if any(value not in {"", "Y", "N", "U"} for value in criteria):
        errors.append(f"{context}: C1-C5 must be blank, Y, N, or U")
    if any(value in {"N", "U"} for value in criteria) and not row.get("annotation_notes", "").strip():
        errors.append(f"{context}: annotation_notes is required when a criterion is N or U")
    return errors


def isu_class(row: dict[str, str]) -> str:
    """Derive the result: failed criterion wins, then uncertainty, else MV-SI."""
    criteria = tuple(row.get(field, "").strip().upper() for field in COMPARE)
    if "N" in criteria:
        return "N"
    if "U" in criteria:
        return "U"
    return "Y"


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
    for key, row in primary.items(): errors += validate_web3_decision(row, f"Web3Bugs primary {key}")
    for key, row in agreement.items(): errors += validate_web3_decision(row, f"Web3Bugs agreement {key}")
    for key, row in isu1.items(): errors += validate_isu_decision(row, f"ISU reviewer 1 {key}")
    for key, row in isu2.items(): errors += validate_isu_decision(row, f"ISU reviewer 2 {key}")
    def derived_label(row: dict[str, str], field: str, positive: str) -> str:
        return row.get(field, "").strip() or (positive if all(v == "Y" for v in normalized_criteria(row)) else "")
    web_disagreements = {key for key, second in agreement.items()
                         if derived_label(primary[key], "label", "TP_MVSI") != derived_label(second, "label", "TP_MVSI")
                         or normalized_criteria(primary[key]) != normalized_criteria(second)}
    isu_disagreements = {key for key in isu1
                         if tuple(isu1[key].get(field, "").strip().upper() or "Y" for field in COMPARE)
                         != tuple(isu2[key].get(field, "").strip().upper() or "Y" for field in COMPARE)}
    web_adj = keyed(args.web3bugs_adjudication, "global_candidate_id") if args.web3bugs_adjudication.is_file() else {}
    isu_adj = keyed(args.isu_adjudication, "oracle_row_id") if args.isu_adjudication.is_file() else {}
    if set(web_adj) != web_disagreements: errors.append("Web3Bugs adjudication does not exactly cover disagreements")
    if set(isu_adj) != isu_disagreements: errors.append("ISU adjudication does not exactly cover disagreements")
    for key, row in web_adj.items():
        if row.get("final_label") not in WEB3_LABELS or not row.get("rationale", "").strip(): errors.append(f"invalid Web3Bugs adjudication: {key}")
    for key, row in isu_adj.items():
        if row.get("adjudicated_is_mvsi", "").strip().upper() not in ISU_DECISIONS or not row.get("rationale", "").strip(): errors.append(f"invalid ISU adjudication: {key}")
    if errors:
        print(json.dumps({"status": "INVALID", "error_count": len(errors), "errors": errors[:200]}, sort_keys=True)); return 1
    args.output.mkdir(parents=True)
    final_web = [{"global_candidate_id": key, "final_label": web_adj[key]["final_label"] if key in web_adj else derived_label(row, "label", "TP_MVSI")}
                 for key, row in sorted(primary.items())]
    final_isu = [{"oracle_row_id": key,
                  "adjudicated_is_mvsi": isu_adj[key]["adjudicated_is_mvsi"].strip().upper() if key in isu_adj else isu_class(row),
                  "adjudicated_class": {"Y": "MV_SI", "N": "NON_MVSI", "U": "INSUFFICIENT_EVIDENCE"}[
                      isu_adj[key]["adjudicated_is_mvsi"].strip().upper() if key in isu_adj else isu_class(row)]}
                 for key, row in sorted(isu1.items())]
    for name, fields, values in (("web3bugs_final.csv", ["global_candidate_id", "final_label"], final_web),
                                 ("isu_final.csv", ["oracle_row_id", "adjudicated_is_mvsi", "adjudicated_class"], final_isu)):
        with (args.output / name).open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(values)
    print(json.dumps({"status": "COMPLETE", "web3bugs": len(final_web), "isu": len(final_isu),
                      "web3bugs_disagreements": len(web_disagreements), "isu_disagreements": len(isu_disagreements)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
