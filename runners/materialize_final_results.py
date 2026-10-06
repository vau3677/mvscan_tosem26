#!/usr/bin/env python3
"""Materialize final Web3Bugs precision and ISU recovery results.

This consumes already-frozen detector/sample artifacts and completed human review.
It does not run MV-Scan or alter any annotation/adjudication input.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from runners.statistics import wilson_95


CONFIGURATIONS = ("B0", "A1", "A2", "A4", "A5")
WEB3_LABELS = {"TP_MVSI", "VALID_OTHER_ISU", "NONBUG", "INSUFFICIENT_EVIDENCE"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def derived_web3_label(row: dict[str, str]) -> str:
    if row.get("review_complete", "").strip().upper() != "Y":
        raise ValueError(f"unfinished Web3Bugs row: {row.get('global_candidate_id', '<missing>')}")
    label = row.get("label", "").strip() or "TP_MVSI"
    if label not in WEB3_LABELS:
        raise ValueError(f"invalid Web3Bugs label: {label}")
    return label


def pct(value: float | None) -> str:
    return "N/A" if value is None else f"{100 * value:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("results/final"))
    args = parser.parse_args()
    root = args.root.resolve()
    output = (root / args.output).resolve() if not args.output.is_absolute() else args.output
    output.mkdir(parents=True, exist_ok=True)

    review_rows = read_csv(root / "human_review/web3bugs_primary.csv")
    keyed_review = {row["global_candidate_id"]: row for row in review_rows}
    if len(review_rows) != 1270 or len(keyed_review) != len(review_rows):
        raise ValueError("Web3Bugs primary review must contain 1,270 unique buckets")
    labels = {key: derived_web3_label(row) for key, row in keyed_review.items()}

    sample = json.loads((root / "freeze/CROSS_ABLATION_SAMPLE.json").read_text(encoding="utf-8"))
    inventory = json.loads((root / "freeze/CROSS_ABLATION_UNION_INVENTORY.json").read_text(encoding="utf-8"))
    by_configuration = sample["selection"]["by_configuration"]
    populations = sample["population_counts"]
    bucket_configurations = {
        bucket["global_candidate_id"]: tuple(bucket["configurations"])
        for bucket in inventory["buckets"]
    }
    config_rows: list[dict[str, object]] = []
    for configuration in CONFIGURATIONS:
        selected = by_configuration[configuration]
        missing = sorted(set(selected) - set(labels))
        if missing:
            raise ValueError(f"{configuration}: {len(missing)} selected buckets lack primary labels")
        config_labels = [labels[key] for key in selected]
        counts = Counter(config_labels)
        total = len(config_labels)
        successes = counts["TP_MVSI"]
        low, high = wilson_95(successes, total)
        resolved_total = total - counts["INSUFFICIENT_EVIDENCE"]
        config_rows.append({
            "configuration": configuration,
            "population_buckets": populations[configuration],
            "audited_buckets": total,
            "tp_mvsi": successes,
            "valid_other_isu": counts["VALID_OTHER_ISU"],
            "nonbug": counts["NONBUG"],
            "insufficient_evidence": counts["INSUFFICIENT_EVIDENCE"],
            "precision": successes / total,
            "wilson_95_low": low,
            "wilson_95_high": high,
            "resolved_case_precision": successes / resolved_total if resolved_total else None,
            "resolved_case_denominator": resolved_total,
            "configuration_only_audited": sum(
                bucket_configurations[key] == (configuration,) for key in selected
            ),
            "configuration_only_tp_mvsi": sum(
                bucket_configurations[key] == (configuration,) and labels[key] == "TP_MVSI"
                for key in selected
            ),
            "precision_delta_vs_b0": None,
        })

    b0_precision = config_rows[0]["precision"]
    for row in config_rows:
        row["precision_delta_vs_b0"] = row["precision"] - b0_precision

    membership_rows: list[dict[str, object]] = []
    for pattern, population_count in sorted(inventory["membership_pattern_counts"].items()):
        configurations = tuple(pattern.split("+"))
        audited_ids = [
            key for key in labels
            if bucket_configurations.get(key) == configurations
        ]
        pattern_labels = Counter(labels[key] for key in audited_ids)
        membership_rows.append({
            "membership_pattern": pattern,
            "population_buckets": population_count,
            "audited_buckets": len(audited_ids),
            "tp_mvsi": pattern_labels["TP_MVSI"],
            "valid_other_isu": pattern_labels["VALID_OTHER_ISU"],
            "nonbug": pattern_labels["NONBUG"],
            "insufficient_evidence": pattern_labels["INSUFFICIENT_EVIDENCE"],
        })

    adjudications = read_csv(root / "benchmarks/isu/adjudications.csv")
    if len(adjudications) != 116:
        raise ValueError("ISU adjudications must contain all 116 historical findings")
    adjudicated = {row["oracle_row_id"]: row for row in adjudications}
    if len(adjudicated) != 116:
        raise ValueError("ISU adjudications contain duplicate oracle_row_id values")
    final_classes = Counter(row["adjudicated_class"] for row in adjudications)
    disagreement_count = sum(bool(row["disagreement_fields"].strip()) for row in adjudications)

    strict_rows = read_csv(root / "benchmarks/isu/strict_match_review.csv")
    strict = {row["oracle_row_id"]: row for row in strict_rows}
    mvsi_ids = {key for key, row in adjudicated.items() if row["adjudicated_class"] == "MV_SI"}
    if set(strict) != mvsi_ids:
        raise ValueError("strict-match census does not exactly cover adjudicated MV_SI rows")
    accepted = [row for row in strict_rows if row["accepted_build"].strip().lower() == "true"]
    unaccepted = [row for row in strict_rows if row["accepted_build"].strip().lower() == "false"]
    if any(row["semantic_match"].strip() not in {"Y", "N"} for row in accepted):
        raise ValueError("every accepted-build MV_SI row needs a Y/N semantic-match decision")
    matches = sum(row["semantic_match"].strip() == "Y" for row in accepted)
    isu_result = {
        "historical_findings": len(adjudications),
        "annotator_disagreements": disagreement_count,
        "adjudicated_mv_si": final_classes["MV_SI"],
        "adjudicated_non_mvsi": final_classes["NON_MVSI"],
        "adjudicated_insufficient_evidence": final_classes["INSUFFICIENT_EVIDENCE"],
        "accepted_builds_among_mv_si": len(accepted),
        "unaccepted_builds_among_mv_si": len(unaccepted),
        "semantic_matches": matches,
        "build_coverage": len(accepted) / len(strict_rows),
        "historical_recovery": matches / len(accepted),
    }

    union_counts = Counter(labels.values())
    result = {
        "schema_version": 1,
        "agreement_review": {"status": "SKIPPED_BY_RESEARCH_TEAM", "metrics_computed": False},
        "web3bugs": {
            "audited_union_buckets": len(review_rows),
            "union_label_counts": dict(sorted(union_counts.items())),
            "population_union_buckets": inventory["union_bucket_count"],
            "overlap_union_buckets": sample["overlap_union_bucket_count"],
            "overlap_selected_buckets": sample["overlap_selected_bucket_count"],
            "by_configuration": config_rows,
            "membership_patterns": membership_rows,
        },
        "isu": isu_result,
    }
    (output / "final_results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(
        output / "web3bugs_precision_by_configuration.csv",
        list(config_rows[0]),
        config_rows,
    )
    write_csv(
        output / "web3bugs_membership_patterns.csv",
        list(membership_rows[0]),
        membership_rows,
    )
    write_csv(output / "isu_recovery.csv", list(isu_result), [isu_result])

    lines = [
        "# Final evaluation results",
        "",
        "These results use the frozen detector runs and samples. No detector run was repeated.",
        "The planned 200-row Web3Bugs agreement review was skipped by the research team; no agreement statistic is reported.",
        "",
        "## Web3Bugs candidate precision",
        "",
        "| Configuration | Disabled component | Population | Audited | TP MV-SI | Nonbug | Precision | Wilson 95% CI | Delta vs. B0 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    disabled_components = {
        "B0": "none (reference)",
        "A1": "branch-derived relations",
        "A2": "multi-return relations",
        "A4": "precise mapping identity",
        "A5": "contextual keys",
    }
    for row in config_rows:
        lines.append(
            f"| {row['configuration']} | {disabled_components[row['configuration']]} | "
            f"{row['population_buckets']} | {row['audited_buckets']} | "
            f"{row['tp_mvsi']} | {row['nonbug']} | {pct(row['precision'])} | "
            f"{pct(row['wilson_95_low'])}–{pct(row['wilson_95_high'])} | "
            f"{100 * row['precision_delta_vs_b0']:+.1f} pp |"
        )
    lines += [
        "",
        f"Across the audited structural union, {union_counts['TP_MVSI']} of {len(review_rows)} buckets were labeled TP MV-SI; "
        f"{union_counts['NONBUG']} were labeled NONBUG.",
        f"The full frozen union contains {inventory['union_bucket_count']} buckets. "
        f"The coordinated samples merge to {len(review_rows)} audited buckets; "
        f"{sample['overlap_selected_bucket_count']} audited buckets occur in more than one configuration sample.",
        "",
        "## Historical ISU recovery",
        "",
        f"The two ISU reviewers disagreed on {disagreement_count} of 116 findings. After adjudication: "
        f"{final_classes['MV_SI']} MV-SI, {final_classes['NON_MVSI']} non-MVSI, and "
        f"{final_classes['INSUFFICIENT_EVIDENCE']} insufficient-evidence findings.",
        "",
        f"Of the {final_classes['MV_SI']} adjudicated MV-SI findings, {len(accepted)} had accepted builds "
        f"({pct(isu_result['build_coverage'])} build coverage). MV-Scan strictly recovered {matches} of {len(accepted)} "
        f"({pct(isu_result['historical_recovery'])}); the {len(unaccepted)} unaccepted-build cases are outside B and were not run.",
        "",
    ]
    (output / "RESULTS_SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"status": "COMPLETE", "output": str(output), "web3bugs": config_rows, "isu": isu_result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
