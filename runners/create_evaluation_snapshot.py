#!/usr/bin/env python3
"""Create the single current evaluation-state checksum manifest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from runners.common import ROOT, canonical_bytes, sha256_file

REQUIRED = [
    "protocol/MVSCAN_EVALUATION_PLAN.md",
    "protocol/WEB3BUGS_REVIEW_GUIDE.md",
    "protocol/annotation_guide.md",
    "benchmarks/isu/oracle_population.csv",
    "benchmarks/isu/source_resolution.csv",
    "benchmarks/isu/execution_subject_map.csv",
    "benchmarks/isu/oracle_build_coverage.csv",
    "benchmarks/web3bugs/accepted_cohort.csv",
    "benchmarks/web3bugs/source_scope.csv",
    "benchmarks/web3bugs/overlap_and_exposure.csv",
    "freeze/CROSS_ABLATION_UNION_INVENTORY.json",
    "freeze/CROSS_ABLATION_SAMPLE.json",
    "freeze/DETERMINISM_REPORT.json",
    "human_review/MANIFEST.json",
    "runners/run_mvscan.py",
    "runners/build_candidate_union.py",
    "runners/rebuild_source_scope.py",
    "runners/prepare_human_handoff.py",
    "runners/validate_human_handoff.py",
    "runners/finalize_human_reviews.py",
    "runners/prepare_isu_strict_match.py",
    "runners/analyze_determinism.py",
    "runners/statistics.py",
    "runners/validate_output.py",
    "tests/test_evaluation_infrastructure.py",
]


def record(path: Path) -> dict[str, object]:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha256_file(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    dynamic = [
        path.relative_to(ROOT).as_posix()
        for pattern in ("configs/*.env", "configs/configurations.json",
                        "benchmarks/subject_manifests/*.json")
        for path in sorted(ROOT.glob(pattern))
    ]
    for relative in (
        "mvscan-smoke/mvscan_plugin/inconsistent_state.py",
        "mvscan-smoke/mvscan_plugin/utils/icfg.py",
        "mvscan-smoke/mvscan_plugin/utils/mvscan_env.py",
        "environment/resource_manifest.json",
        "environment/environment_manifest.json",
        "environment/frozen_svm_compilers.json",
        "environment/daemonless_environment_manifest.json",
        "deviations/deviation_log.csv",
    ):
        if (ROOT / relative).is_file():
            dynamic.append(relative)
    required = list(dict.fromkeys(REQUIRED + sorted(dynamic)))
    missing = [relative for relative in required if not (ROOT / relative).is_file()]
    if missing:
        raise RuntimeError(f"required current artifacts missing: {missing}")
    run_manifests = sorted((ROOT / "runs").glob("*/run_manifest.json"))
    run_records = []
    for path in run_manifests:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        run_records.append({**record(path), "run_id": manifest.get("run_id"),
                            "dataset": manifest.get("dataset"), "subject": str(manifest.get("subject")),
                            "configuration": manifest.get("configuration"), "seed": manifest.get("python_hash_seed"),
                            "terminal_status": manifest.get("terminal_status"),
                            "canonical_json_sha256": manifest.get("canonical_json_sha256")})
    union = json.loads((ROOT / "freeze/CROSS_ABLATION_UNION_INVENTORY.json").read_text(encoding="utf-8"))
    handoff = json.loads((ROOT / "human_review/MANIFEST.json").read_text(encoding="utf-8"))
    result = {"schema_version": 1, "status": "READY_FOR_HUMAN_REVIEW",
              "authority": "protocol/MVSCAN_EVALUATION_PLAN.md",
              "raw_detector_runs_modified": False,
              "current_artifacts": [record(ROOT / relative) for relative in required],
              "run_manifests": run_records,
              "summary": {"terminal_run_manifests": len(run_records),
                  "union_buckets": union["union_bucket_count"],
                  "web3bugs_review_units": handoff["web3bugs"]["primary"],
                  "web3bugs_agreement_units": handoff["web3bugs"]["agreement"],
                  "isu_findings_per_reviewer": handoff["isu"]["findings"],
                  "isu_source_grounded": handoff["isu"]["source_grounded"]}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(canonical_bytes(result).decode("utf-8") + "\n")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
