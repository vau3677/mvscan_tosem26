#!/usr/bin/env python3
"""Generate the six manuscript-facing tables required by the evaluation plan."""
from __future__ import annotations

import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "final"
CONFIGURATIONS = ("B0", "A1", "A2", "A4", "A5")


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def write_csv(name: str, rows: list[dict[str, object]]) -> None:
    with (OUTPUT / name).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def percentage(numerator: int, denominator: int) -> str:
    return "N/A" if not denominator else f"{100 * numerator / denominator:.1f}%"


def quantile(values: list[float], probability: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    index = (len(ordered) - 1) * probability
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    final = json.loads((OUTPUT / "final_results.json").read_text(encoding="utf-8"))
    build = json.loads((ROOT / "benchmarks/build_best_effort_summary.json").read_text(encoding="utf-8"))
    inventory = json.loads((ROOT / "freeze/CROSS_ABLATION_UNION_INVENTORY.json").read_text(encoding="utf-8"))
    determinism = json.loads((ROOT / "freeze/DETERMINISM_REPORT.json").read_text(encoding="utf-8"))

    table1 = [
        {
            "benchmark": "Published ISU findings",
            "initial_population": 116,
            "exact_source_revision_resolved": build["isu"]["exact_resolved_findings"],
            "accepted_builds": build["isu"]["oracle_build_coverage_counts"]["COMPILED"],
            "excluded_or_unbuilt": build["isu"]["oracle_build_coverage_counts"]["ACQUISITION_FAILURE"],
            "build_coverage": percentage(build["isu"]["oracle_build_coverage_counts"]["COMPILED"], 116),
        },
        {
            "benchmark": "Web3Bugs snapshots",
            "initial_population": build["web3bugs"]["population_snapshots"],
            "exact_source_revision_resolved": build["web3bugs"]["population_snapshots"],
            "accepted_builds": build["web3bugs"]["snapshots_with_accepted_compilation"],
            "excluded_or_unbuilt": build["web3bugs"]["population_snapshots"] - build["web3bugs"]["snapshots_with_accepted_compilation"],
            "build_coverage": percentage(build["web3bugs"]["snapshots_with_accepted_compilation"], build["web3bugs"]["population_snapshots"]),
        },
    ]

    isu = final["isu"]
    oracle = csv_rows(ROOT / "benchmarks/isu/oracle_population.csv")
    exact_fix_eligible = sum(bool(row["exact_fixed_revision"].strip()) for row in oracle)
    table2 = [{
        "historical_findings": isu["historical_findings"],
        "mv_si": isu["adjudicated_mv_si"],
        "non_mvsi": isu["adjudicated_non_mvsi"],
        "insufficient_evidence": isu["adjudicated_insufficient_evidence"],
        "mv_si_with_accepted_build": isu["accepted_builds_among_mv_si"],
        "strict_matches": isu["semantic_matches"],
        "strict_recovery": percentage(isu["semantic_matches"], isu["accepted_builds_among_mv_si"]),
        "exact_fix_controls_eligible": exact_fix_eligible,
        "exact_fix_controls_run": 0,
    }]

    table3 = []
    for row in final["web3bugs"]["by_configuration"]:
        table3.append({
            "configuration": row["configuration"],
            "audited": row["audited_buckets"],
            "tp_mvsi": row["tp_mvsi"],
            "valid_other_isu": row["valid_other_isu"],
            "nonbug": row["nonbug"],
            "insufficient_evidence": row["insufficient_evidence"],
            "precision": f"{100 * row['precision']:.1f}%",
            "wilson_95_ci": f"[{100 * row['wilson_95_low']:.1f}%, {100 * row['wilson_95_high']:.1f}%]",
            "agreement": "Skipped; not reported",
        })

    config_only_population = {
        pattern: count for pattern, count in inventory["membership_pattern_counts"].items()
        if "+" not in pattern
    }
    table4 = []
    for row in final["web3bugs"]["by_configuration"]:
        configuration = row["configuration"]
        table4.append({
            "configuration": configuration,
            "native_candidates": inventory["native_candidate_counts"][configuration],
            "in_scope_structural_buckets": row["population_buckets"],
            "audited_buckets": row["audited_buckets"],
            "configuration_only_population": config_only_population.get(configuration, 0),
            "configuration_only_audited": row["configuration_only_audited"],
            "configuration_only_tp_mvsi": row["configuration_only_tp_mvsi"],
            "precision_delta_vs_b0": f"{100 * row['precision_delta_vs_b0']:+.1f} pp",
        })

    snapshot = json.loads((ROOT / "freeze/EVALUATION_SNAPSHOT.json").read_text(encoding="utf-8"))
    frozen_manifests = []
    for item in snapshot["run_manifests"]:
        path = ROOT / item["path"]
        if path.is_file():
            frozen_manifests.append(json.loads(path.read_text(encoding="utf-8")))
    all_manifests = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (ROOT / "runs").glob("*/run_manifest.json")
    ]
    table5 = []
    for dataset in ("isu", "web3bugs"):
        for configuration in CONFIGURATIONS:
            frozen_selected = [
                row for row in frozen_manifests
                if row["dataset"] == dataset
                and row["configuration"] == configuration
                and str(row.get("python_hash_seed")) == "0"
            ]
            current_selected = [
                row for row in all_manifests
                if row["dataset"] == dataset
                and row["configuration"] == configuration
                and str(row.get("python_hash_seed")) == "0"
            ]
            subjects = sorted({row["subject"] for row in current_selected})
            # Preserve each frozen successful run. For an originally failed subject,
            # use its accepted post-freeze compatibility-recovery success, if any.
            successes = []
            for subject in subjects:
                frozen_success = [
                    row for row in frozen_selected
                    if row["subject"] == subject and row["terminal_status"] == "SUCCESS"
                ]
                recovered_success = [
                    row for row in current_selected
                    if row["subject"] == subject and row["terminal_status"] == "SUCCESS"
                ]
                choices = frozen_success or recovered_success
                if choices:
                    successes.append(sorted(choices, key=lambda row: row["attempt_id"])[0])
            runtimes = [float(row["elapsed_seconds"]) for row in successes]
            memories = [int(row["peak_rss_bytes"]) / (1024 ** 2) for row in successes]
            det = determinism["datasets"][dataset] if configuration == "B0" else None
            table5.append({
                "benchmark": dataset,
                "configuration": configuration,
                "attempted": len(subjects),
                "successful": len(successes),
                "completion": percentage(len(successes), len(subjects)),
                "runtime_median_s": f"{statistics.median(runtimes):.2f}" if runtimes else "N/A",
                "runtime_iqr_s": f"{quantile(runtimes, .25):.2f}–{quantile(runtimes, .75):.2f}" if runtimes else "N/A",
                "runtime_max_s": f"{max(runtimes):.2f}" if runtimes else "N/A",
                "peak_rss_median_mib": f"{statistics.median(memories):.1f}" if memories else "N/A",
                "peak_rss_max_mib": f"{max(memories):.1f}" if memories else "N/A",
                "timeouts": sum(any(bool(row.get("timed_out")) for row in current_selected if row["subject"] == subject) and subject not in {row["subject"] for row in successes} for subject in subjects),
                "oom": sum(any(bool(row.get("oom_killed")) for row in current_selected if row["subject"] == subject) and subject not in {row["subject"] for row in successes} for subject in subjects),
                "context_bound": sum(any(bool(row.get("context_bound_failure")) for row in current_selected if row["subject"] == subject) and subject not in {row["subject"] for row in successes} for subject in subjects),
                "seed_pairs": det["paired_successes"] if det else "—",
                "exact_seed_matches": det["exact_matches"] if det else "—",
                "seed_mismatches": len(det["mismatches"]) if det else "—",
                "missing_seed_pairs": len(det["missing_pairs"]) if det else "—",
            })

    web3 = csv_rows(ROOT / "human_review/web3bugs_primary.csv")
    causes = Counter(row["nonbug_primary_cause"].strip() for row in web3 if row["label"].strip() == "NONBUG")
    cause_labels = {
        "no_desynchronizing_partial_transition": "No desynchronizing partial transition",
        "reconciliation_precedes_consumption": "Reconciliation precedes consumption",
        "analysis_abstraction_error": "Analysis abstraction error",
        "unsupported_or_overbroad_relation": "Unsupported or overbroad relation",
        "incompatible_context_key_or_ordering": "Incompatible context/key/ordering",
        "omitted_state_not_behaviorally_consumed": "Omitted state not behaviorally consumed",
    }
    table6 = [{
        "category": cause_labels[key],
        "count": count,
        "share_of_nonbugs": percentage(count, sum(causes.values())),
    } for key, count in causes.most_common()]
    table6.append({
        "category": "Separately consolidated and validated new findings",
        "count": "—",
        "share_of_nonbugs": "Not yet determined; validation stage not performed",
    })

    tables = [table1, table2, table3, table4, table5, table6]
    names = [
        "table1_benchmark_build_coverage.csv",
        "table2_historical_recovery.csv",
        "table3_candidate_precision.csv",
        "table4_cross_ablation.csv",
        "table5_determinism_scalability.csv",
        "table6_error_analysis_validated_findings.csv",
    ]
    for name, rows in zip(names, tables):
        write_csv(name, rows)

    captions = [
        "Benchmark populations and best-effort no-edit build coverage.",
        "Historical ISU classification and strict semantic recovery.",
        "Candidate labels and per-configuration precision.",
        "Cross-ablation candidate populations and configuration-specific buckets.",
        "Completion, runtime, memory, and deterministic reproducibility.",
        "Primary causes of Web3Bugs nonbugs and separately validated findings.",
    ]
    notes = [
        "ISU build coverage here covers all 116 findings; Table 2 reports coverage within adjudicated MV-SI cases.",
        "Only accepted-build MV-SI cases enter the strict-recovery denominator. No exact fixed revisions were predeclared, so no exact-fix control was eligible.",
        "Wilson intervals are computed separately. Agreement was skipped by team decision and must not be reported as zero.",
        f"The frozen union contains {final['web3bugs']['population_union_buckets']} buckets; the five samples merge to {final['web3bugs']['audited_union_buckets']}, including {final['web3bugs']['overlap_selected_buckets']} sampled buckets shared across configurations.",
        "Runtime and RSS preserve frozen successful seed-0 runs and use accepted compatibility-recovery runs only for subjects that originally failed. Determinism columns apply only to the frozen B0 seed-0/seed-1 comparison.",
        "The 301 TP_MVSI structural buckets are candidate-level classifications, not consolidated novel findings.",
    ]
    lines = ["# Paper-facing result tables", ""]
    for index, (caption, note, rows) in enumerate(zip(captions, notes, tables), 1):
        lines += [f"## Table {index}. {caption}", ""]
        fields = list(rows[0])
        lines += ["| " + " | ".join(field.replace("_", " ").title() for field in fields) + " |"]
        lines += ["| " + " | ".join("---" for _ in fields) + " |"]
        for row in rows:
            lines += ["| " + " | ".join(str(row[field]) for field in fields) + " |"]
        lines += ["", f"*Note:* {note}", ""]
    (OUTPUT / "PAPER_TABLES.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"status": "COMPLETE", "tables": names, "markdown": "results/final/PAPER_TABLES.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
