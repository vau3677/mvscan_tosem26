#!/usr/bin/env python3
"""Requirement-by-requirement F1 readiness gate and optional sealer."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from runners.common import ROOT, sha256_file, write_json_new
from runners.configuration import CONFIG_NAMES, load_named
from runners.validate_human_materials import oracle_record_errors
from runners.validate_output import EXPECTED_DETECTOR_HASHES

COMPLETE = "COMPLETE"
DEFERRED = "DEFERRED_UNDER_OPTION_B"
BHA = "BLOCKED_HUMAN_ANNOTATION"
BHJ = "BLOCKED_HUMAN_ADJUDICATION"
BHO = "BLOCKED_HUMAN_ORACLE"
BED = "BLOCKED_EXPOSURE_DECLARATION"
BBR = "BLOCKED_BUILD_RECONSTRUCTION"
BEN = "BLOCKED_ENVIRONMENT"
BVA = "BLOCKED_VALIDATION"
ALLOWED = {COMPLETE, DEFERRED, BHA, BHJ, BHO, BED, BBR, BEN, BVA}
PROTOCOL_HASH = "798f46164e1b3b30496573f094625130b9542f6a7ed11d33a4b30159a54eccf7"
HISTORICAL_COMMIT = "985e0032449aaa4fec4b6d2f9f7902525cbbb736"
WEB3BUGS_COMMIT = "fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4"
CLASSES = {"MV_SI", "SV_SI", "ISU_OTHER", "OTHER", "INSUFFICIENT_EVIDENCE"}
ANNOTATION_REQUIRED = (
    "evidence_sufficient", "C1", "C2", "C3", "C4", "C5", "semantic_class",
    "semantic_relation_entities", "semantic_core", "writer_transition",
    "written_roles", "omitted_roles", "persistent_read", "sink_or_effect",
    "required_ordering", "reconciliation_point", "evidence_references",
)
ORACLE_FIELDS = {
    "oracle_row_id", "required_relation_core", "required_writer_transition",
    "required_written_roles", "required_omitted_roles", "required_persistent_read",
    "required_sink_kind", "required_ordering", "reconciliation_point",
    "evidence_references",
}


def rows(relative: str) -> list[dict[str, str]]:
    with (ROOT / relative).open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def check(status: str, evidence: object, detail: str = "") -> dict[str, object]:
    if status not in ALLOWED:
        raise ValueError(status)
    return {"status": status, "evidence": evidence, "detail": detail}


def git_identity(relative: str) -> tuple[str, bool]:
    path = ROOT / relative
    commit = subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", path, "status", "--porcelain"], text=True).strip())
    return commit, dirty


def annotations_complete(data, expected_ids, annotator):
    return (
        len(data) == len(expected_ids)
        and {row.get("oracle_row_id") for row in data} == expected_ids
        and {row.get("annotator_id") for row in data} == {annotator}
        and all(
            all(row.get(field, "").strip() for field in ANNOTATION_REQUIRED)
            and row.get("semantic_class") in CLASSES
            and row.get("evidence_sufficient") in {"true", "false"}
            and all(row.get(field) in {"true", "false"} for field in ("C1", "C2", "C3", "C4", "C5"))
            for row in data
        )
    )


def read_oracles(path: Path):
    result = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                result.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return result, False
    valid = all(not oracle_record_errors(row) for row in result)
    return result, valid


def assess(attempt: Path) -> dict[str, object]:
    output = {}
    detector_root = ROOT / "mvscan-smoke" / "mvscan_plugin"
    actual_hashes = {
        "inconsistent_state": sha256_file(detector_root / "inconsistent_state.py"),
        "icfg": sha256_file(detector_root / "utils" / "icfg.py"),
        "mvscan_env": sha256_file(detector_root / "utils" / "mvscan_env.py"),
    }
    output["F0 detector hashes"] = check(COMPLETE if actual_hashes == EXPECTED_DETECTOR_HASHES else BVA, actual_hashes)
    protocol_path = ROOT / "protocol" / "MVSCAN_EVALUATION_PLAN.md"
    protocol_hash = sha256_file(protocol_path)
    output["protocol hash"] = check(COMPLETE if protocol_hash == PROTOCOL_HASH else BVA, protocol_hash)
    option_b_path = ROOT / "freeze" / "OPTION_B_BLIND_EXECUTION.json"
    option_b = json.loads(option_b_path.read_text(encoding="utf-8")) if option_b_path.is_file() else {}
    amendment_path = ROOT / str(option_b.get("amendment_path", "missing"))
    option_b_valid = (
        option_b.get("status") == "ADOPTED"
        and option_b.get("decision") == "OPTION_B_BLIND_EXECUTION"
        and option_b.get("human_work_deferred_until_before_unblinding") is True
        and option_b.get("semantic_output_inspected") is False
        and amendment_path.is_file()
        and sha256_file(amendment_path) == option_b.get("amendment_sha256")
    )
    output["Option B blind-execution amendment"] = check(COMPLETE if option_b_valid else BVA, option_b)

    historical_commit, historical_dirty = git_identity("benchmarks/sources/SolidityStateStudy")
    web_commit, web_dirty = git_identity("benchmarks/sources/Web3Bugs")
    output["historical repository and commit"] = check(
        COMPLETE if historical_commit == HISTORICAL_COMMIT and not historical_dirty else BVA,
        {"commit": historical_commit, "dirty": historical_dirty},
    )
    output["Web3Bugs repository and commit"] = check(
        COMPLETE if web_commit == WEB3BUGS_COMMIT and not web_dirty else BVA,
        {"commit": web_commit, "dirty": web_dirty},
    )

    historical = rows("benchmarks/isu/oracle_population.csv")
    historical_ids = {row.get("oracle_row_id") for row in historical}
    historical_valid = len(historical) == 116 and len(historical_ids) == 116 and None not in historical_ids
    output["exact 116-row historical population"] = check(
        COMPLETE if historical_valid else BVA,
        {"rows": len(historical), "unique_ids": len(historical_ids)},
    )
    web = rows("benchmarks/web3bugs/population.csv")
    web_ids = {row.get("snapshot_id") for row in web}
    web_valid = len(web) == 102 and len(web_ids) == 102 and all(row.get("snapshot_sha256") for row in web)
    output["complete Web3Bugs initial population"] = check(
        COMPLETE if web_valid else BVA,
        {"rows": len(web), "unique_ids": len(web_ids)},
    )
    source_manifest = rows("benchmarks/isu/source_manifest.csv")
    sources_valid = (
        bool(source_manifest)
        and all(row.get("sha256") for row in source_manifest)
        and all(row.get("snapshot_sha256") and row.get("solidity_sha256") for row in web)
    )
    output["source hashes"] = check(
        COMPLETE if sources_valid else BVA,
        {"historical_manifest_rows": len(source_manifest), "web3bugs_snapshots": len(web)},
    )

    compilation_seal_path = ROOT / "freeze" / "F1_compilation_freeze.json"
    compilation_seal = json.loads(compilation_seal_path.read_text(encoding="utf-8")) if compilation_seal_path.is_file() else {}
    sealed_artifacts_valid = compilation_seal.get("status") == "SEALED" and all(
        (ROOT / artifact["path"]).is_file()
        and sha256_file(ROOT / artifact["path"]) == artifact["sha256"]
        and (ROOT / artifact["path"]).stat().st_size == artifact["byte_size"]
        for artifact in compilation_seal.get("artifacts", [])
    )
    compilation_valid = (
        sealed_artifacts_valid
        and compilation_seal.get("cohort_rows") == 171
        and compilation_seal.get("exclusion_rows") == 47
        and compilation_seal.get("datasets", {}).get("isu", {}).get("compiled_findings") == 106
        and compilation_seal.get("datasets", {}).get("web3bugs", {}).get("compiled_snapshots") == 65
    )
    output["sealed compilation cohort"] = check(COMPLETE if compilation_valid else BBR, compilation_seal)

    execution = rows("benchmarks/execution_subjects.csv")
    execution_ids = {(row.get("dataset"), row.get("execution_subject_id")) for row in execution}
    execution_valid = (
        len(execution) == len(execution_ids) == 153
        and sum(int(row.get("mapped_item_count", 0)) for row in execution) == 171
        and sum(row.get("dataset") == "isu" for row in execution) == 88
        and sum(row.get("dataset") == "web3bugs" for row in execution) == 65
        and all(row.get("accepted_attempt_id") and row.get("workspace") and row.get("artifact_sha256") for row in execution)
    )
    output["canonical deduplicated execution cohort"] = check(
        COMPLETE if execution_valid else BBR,
        {"execution_subjects": len(execution), "mapped_items": sum(int(row.get("mapped_item_count", 0)) for row in execution)},
    )
    subject_paths = sorted((ROOT / "benchmarks" / "subject_manifests").glob("*.json"))
    subject_documents = []
    subject_valid = True
    for path in subject_paths:
        try: document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): subject_valid = False; continue
        subject_documents.append(document)
        identity = (document.get("dataset"), document.get("subject_id"))
        subject_valid = subject_valid and identity in execution_ids and document.get("accepted_build") is True and bool(document.get("expected_compilation_units")) and bool(document.get("snapshot_paths"))
    subject_identities = {(row.get("dataset"), row.get("subject_id")) for row in subject_documents}
    subject_valid = subject_valid and len(subject_documents) == len(subject_identities) == 153 and subject_identities == execution_ids
    output["153 execution subject manifests"] = check(
        COMPLETE if subject_valid else BBR,
        {"manifests": len(subject_documents), "expected": 153},
    )

    scope = rows("benchmarks/web3bugs/source_scope.csv")
    expected_scope = sum(int(row["solidity_file_count"]) for row in web)
    scope_valid = (
        len(scope) == expected_scope
        and {row.get("snapshot_id") for row in scope} == web_ids
        and all(row.get("scope") in {"IN_SCOPE", "OUT_OF_SCOPE"} and row.get("source_sha256") for row in scope)
    )
    output["source-scope records"] = check(
        COMPLETE if scope_valid else BVA,
        {"rows": len(scope), "expected_rows": expected_scope},
    )
    overlap = rows("benchmarks/web3bugs/overlap_and_exposure.csv")
    overlap_valid = (
        len(overlap) == len(web)
        and {row.get("snapshot_id") for row in overlap} == web_ids
        and all(row.get("benchmark_overlap") in {"true", "false"} and row.get("overlap_basis") for row in overlap)
    )
    output["overlap records"] = check(COMPLETE if overlap_valid else BVA, {"rows": len(overlap)})
    historical_exposure = rows("benchmarks/isu/exposure.csv")
    exposure = historical_exposure + overlap
    exposure_valid = (
        len(historical_exposure) == 116
        and len(overlap) == 102
        and all(
            row.get("pre_freeze_exposure") in {"true", "false"}
            and all(row.get(field, "").strip() for field in ("exposure_note", "reviewed_by", "reviewed_at"))
            for row in exposure
        )
    )
    output["development-exposure declarations"] = check(
        COMPLETE if exposure_valid else (DEFERRED if option_b_valid else BED),
        {"reviewed": sum(bool(row.get("reviewed_by")) for row in exposure), "required": len(exposure)},
    )

    protocol_lines = protocol_path.read_text(encoding="utf-8").splitlines()
    guide = (ROOT / "protocol" / "annotation_guide.md").read_text(encoding="utf-8")
    c_rows = [line for line in protocol_lines if line.startswith("| **C") and ": " in line]
    guide_valid = len(c_rows) == 5 and all(line in guide for line in c_rows)
    output["C1-C5 guide"] = check(
        COMPLETE if guide_valid else BVA,
        {"verbatim_rows": sum(line in guide for line in c_rows), "required": 5},
    )
    first = rows("benchmarks/isu/annotations_annotator_1.csv")
    second = rows("benchmarks/isu/annotations_annotator_2.csv")
    first_complete = annotations_complete(first, historical_ids, "annotator_1")
    second_complete = annotations_complete(second, historical_ids, "annotator_2")
    annotation_ready = first_complete and second_complete
    output["two independent historical annotations"] = check(
        COMPLETE if annotation_ready else (DEFERRED if option_b_valid else BHA),
        {"annotator_1_complete": first_complete, "annotator_2_complete": second_complete},
    )

    adjudications = rows("benchmarks/isu/adjudications.csv")
    disagreements = set()
    if annotation_ready:
        left = {row["oracle_row_id"]: row for row in first}
        right = {row["oracle_row_id"]: row for row in second}
        compared = ("evidence_sufficient", "C1", "C2", "C3", "C4", "C5", "semantic_class")
        disagreements = {
            row_id for row_id in historical_ids
            if any(left[row_id][field] != right[row_id][field] for field in compared)
        }
    adjudicated = {
        row.get("oracle_row_id") for row in adjudications
        if row.get("adjudicated_class") in CLASSES
        and all(row.get(field) for field in ("adjudicator_id", "adjudication_rationale", "evidence_references", "adjudicated_at"))
    }
    adjudication_ready = (
        annotation_ready
        and disagreements == adjudicated
        and len(adjudications) == len(adjudicated)
    )
    output["historical disagreement adjudication"] = check(
        COMPLETE if adjudication_ready else (DEFERRED if option_b_valid else BHJ),
        {"disagreements": len(disagreements), "completed_adjudications": len(adjudicated)},
    )
    final_classes = {}
    if adjudication_ready:
        left = {row["oracle_row_id"]: row for row in first}
        decided = {row["oracle_row_id"]: row["adjudicated_class"] for row in adjudications}
        final_classes = {row_id: decided.get(row_id, left[row_id]["semantic_class"]) for row_id in historical_ids}
    h_path = ROOT / "freeze" / "historical_denominators.json"
    h_valid = False
    if h_path.is_file() and adjudication_ready:
        h = json.loads(h_path.read_text(encoding="utf-8"))
        h_valid = h.get("H") == sum(value == "MV_SI" for value in final_classes.values()) and bool(h.get("adjudicated_population_sha256"))
    output["frozen H"] = check(
        COMPLETE if h_valid else (DEFERRED if option_b_valid else (BHJ if not adjudication_ready else BVA)),
        {"artifact_exists": h_path.is_file()},
    )
    oracles, oracle_syntax = read_oracles(ROOT / "benchmarks" / "isu" / "semantic_match_oracles.jsonl")
    required_oracles = {row_id for row_id, value in final_classes.items() if value == "MV_SI"}
    oracle_ids = {row.get("oracle_row_id") for row in oracles}
    oracle_valid = (
        adjudication_ready
        and oracle_syntax
        and len(oracles) == len(oracle_ids)
        and oracle_ids == required_oracles
    )
    output["minimal semantic-match oracles"] = check(
        COMPLETE if oracle_valid else (DEFERRED if option_b_valid else BHO),
        {"required": len(required_oracles), "valid_rows": len(oracles)},
    )

    configuration_hashes = {}
    configurations_valid = True
    try:
        for name in CONFIG_NAMES:
            load_named(name)
            configuration_hashes[name] = sha256_file(ROOT / "configs" / (name + ".env"))
    except (OSError, ValueError):
        configurations_valid = False
    output["B0/A1/A2/A4/A5 configurations"] = check(
        COMPLETE if configurations_valid else BVA, configuration_hashes
    )
    resource = json.loads((ROOT / "environment" / "resource_manifest.json").read_text(encoding="utf-8"))
    expected_resource = {
        "cpu_vcpus": 4, "memory_bytes": 34359738368, "swap": "disabled",
        "build_timeout_seconds": 900, "analysis_timeout_seconds": 1800,
        "concurrency_per_allocation": 1, "architecture": "linux/amd64",
        "timezone": "UTC", "analysis_network": "disabled",
        "working_path": "/workspace", "restore_immutable_snapshot_before_each_run": True,
    }
    resource_valid = all(resource.get(key) == value for key, value in expected_resource.items())
    output["resource manifest"] = check(COMPLETE if resource_valid else BVA, resource)
    environment = json.loads((ROOT / "environment" / "environment_manifest.json").read_text(encoding="utf-8"))
    oci = json.loads((ROOT / "environment" / "oci_environment_manifest.json").read_text(encoding="utf-8"))
    daemonless_path = ROOT / "environment" / "daemonless_environment_manifest.json"
    daemonless = json.loads(daemonless_path.read_text(encoding="utf-8")) if daemonless_path.is_file() else {}
    oci_valid = (
        oci.get("status") == COMPLETE
        and isinstance(oci.get("image_digest"), str)
        and environment.get("immutable_oci_digest") == oci.get("image_digest")
        and daemonless.get("status") == COMPLETE
        and environment.get("immutable_runtime_digest") == daemonless.get("runtime_digest")
        and daemonless.get("validation", {}).get("network_blocked") is True
        and daemonless.get("validation", {}).get("root_read_only") is True
        and daemonless.get("validation", {}).get("rlimit_as") == [34359738368, 34359738368]
        and len(daemonless.get("validation", {}).get("affinity", [])) == 4
    )
    output["immutable daemonless runtime digest"] = check(
        COMPLETE if oci_valid else BEN,
        {"base_image_digest": oci.get("image_digest"), "runtime_digest": daemonless.get("runtime_digest"), "validation": daemonless.get("validation")},
    )
    compiler = json.loads((ROOT / "environment" / "compiler_inventory.json").read_text(encoding="utf-8"))
    node = json.loads((ROOT / "environment" / "node_toolchain_inventory.json").read_text(encoding="utf-8"))
    svm = json.loads((ROOT / "environment" / "frozen_svm_compilers.json").read_text(encoding="utf-8"))
    toolchains_valid = (
        environment.get("status") == COMPLETE and compiler.get("status") == COMPLETE and node.get("status") == COMPLETE
        and len(svm.get("compilers", [])) >= 33
        and daemonless.get("validation", {}).get("node18") == "v18.20.8"
        and daemonless.get("validation", {}).get("node22") == "v22.13.0"
    )
    output["toolchain identities"] = check(
        COMPLETE if toolchains_valid else BEN,
        {"environment": environment.get("status"), "compiler": compiler.get("status"), "node": node.get("status")},
    )

    test = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "-v", "tests.test_evaluation_infrastructure"],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
    )
    (attempt / "tests.stdout.log").write_text(test.stdout, encoding="utf-8")
    (attempt / "tests.stderr.log").write_text(test.stderr, encoding="utf-8")
    for name in ("runner tests", "validator tests", "canonicalizer tests", "deterministic selector tests"):
        output[name] = check(COMPLETE if test.returncode == 0 else BVA, {"exit_code": test.returncode})
    deviations = rows("deviations/deviation_log.csv")
    required_deviation_fields = {
        "deviation_id", "date", "reason", "affected_subjects",
        "affected_artifacts", "semantic_output_inspected", "impact_on_claims",
    }
    deviation_valid = all(
        set(row) == required_deviation_fields
        and row.get("deviation_id")
        and row.get("semantic_output_inspected") in {"true", "false"}
        for row in deviations
    )
    output["deviation log"] = check(COMPLETE if deviation_valid else BVA, {"rows": len(deviations)})

    blockers = sorted({value["status"] for value in output.values() if value["status"] not in {COMPLETE, DEFERRED}})
    return {
        "schema_version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sealed": False,
        "checks": output,
        "blocking_statuses": blockers,
        "all_requirements_complete": not blockers,
    }


def markdown(readiness):
    lines = [
        "# F1 Readiness", "",
        "All requirements complete: " + str(readiness["all_requirements_complete"]).lower(),
        "", "| Requirement | Status | Detail |", "| --- | --- | --- |",
    ]
    for name, value in readiness["checks"].items():
        detail = str(value.get("detail") or "").replace("|", "\\|")
        lines.append(f"| {name} | {value['status']} | {detail} |")
    lines.extend(["", "## Blocking statuses", ""])
    lines.extend("- " + status for status in readiness["blocking_statuses"])
    if not readiness["blocking_statuses"]:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def dependencies():
    paths = [
        "freeze/F0_manifest.json", "freeze/protocol_manifest.json",
        "freeze/F1_compilation_freeze.json", "freeze/OPTION_B_BLIND_EXECUTION.json",
        "protocol/OPTION_B_BLIND_EXECUTION_AMENDMENT.md",
        "protocol/F2_LOSSLESS_STORAGE_AMENDMENT.md",
"detector/detector_manifest.json",
        "protocol/MVSCAN_EVALUATION_PLAN.md", "protocol/annotation_guide.md",
        "protocol/semantic_match_schema.json", "benchmarks/source_checkouts.json",
        "benchmarks/isu/oracle_population.csv", "benchmarks/isu/source_manifest.csv",
        "benchmarks/web3bugs/population.csv", "benchmarks/web3bugs/build_attempts.csv",
        "benchmarks/web3bugs/accepted_cohort.csv", "benchmarks/web3bugs/source_scope.csv",
        "benchmarks/execution_subjects.csv", "benchmarks/isu/execution_subject_map.csv",
        "reports/FROZEN_COMPILATION_COHORT.csv", "reports/COMPILATION_EXCLUSIONS.csv",
        "environment/environment_manifest.json", "environment/oci_environment_manifest.json",
        "environment/daemonless_environment_manifest.json", "environment/frozen_svm_compilers.json",
        "environment/compiler_inventory.json", "environment/node_toolchain_inventory.json",
        "environment/resource_manifest.json", "environment/python.lock",
        "configs/configurations.json", "runners/common.py", "runners/run_mvscan.py", "runners/validate_output.py",
        "runners/artifact_storage.py", "runners/migrate_run_storage.py",
        "runners/prune_nonaccepted_build_residue.py",
        "runners/canonicalize_json.py", "runners/select_samples.py", "runners/check_f1.py",
        "deviations/deviation_log.csv",
        "protocol/HUMAN_ACTIONS.md",
        "benchmarks/isu/build_screen_summary.json",
        "benchmarks/web3bugs/build_evidence.json",
        "benchmarks/web3bugs/build_screen_summary.json",
        "environment/Dockerfile",
        "environment/python_artifacts.json",
        "environment/installed_python_inventory.json",
        "environment/os_package_inventory.json",
        "environment/foundry_manifest.json",
        "runners/configuration.py",
        "runners/container_exec.py",
        "runners/resource_exec.py",
        "runners/statistics.py",
        "runners/validate_human_materials.py",
        "runners/begin_f2.py",
        "runners/prepare_f2_plan.py", "runners/prepare_subject_manifests.py",
        "runners/validate_daemonless_environment.py",
        "mvscan-smoke/mvscan_plugin/metadata_only.py", "mvscan-smoke/mvscan_plugin/__init__.py",
        "tests/__init__.py", "tests/test_evaluation_infrastructure.py",
        "schemas/annotation_classes.json",
        "freeze/F2_run_plan.json",
    ]
    paths.extend("configs/" + name + ".env" for name in CONFIG_NAMES)
    paths.extend(
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "benchmarks" / "isu" / "evidence_packets").glob("*.json"))
    )
    plan_path = ROOT / "freeze" / "F2_run_plan.json"
    if plan_path.is_file():
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        paths.extend(str(row["subject_manifest"]) for row in plan.get("runs", []))
    result = []
    for relative in sorted(paths):
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError("cannot seal; dependency missing: " + relative)
        result.append({"relative_path": relative, "byte_size": path.stat().st_size, "sha256": sha256_file(path)})
    return result


def publish(readiness, attempt):
    attempt_json = attempt / "F1_readiness.json"
    attempt_report = attempt / "F1_READINESS.md"
    write_json_new(attempt_json, readiness)
    attempt_report.write_text(markdown(readiness), encoding="utf-8", newline="\n")
    for source, target in (
        (attempt_json, ROOT / "freeze" / "F1_readiness.json"),
        (attempt_report, ROOT / "reports" / "F1_READINESS.md"),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        shutil.copyfile(source, temporary)
        os.replace(temporary, target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seal", action="store_true")
    args = parser.parse_args()
    attempt_name = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex
    attempt = ROOT / "freeze" / "readiness_attempts" / attempt_name
    attempt.mkdir(parents=True)
    readiness = assess(attempt)
    publish(readiness, attempt)
    if not args.seal:
        print(json.dumps({"sealed": False, "blocking_statuses": readiness["blocking_statuses"]}, sort_keys=True))
        return 0
    if not readiness["all_requirements_complete"]:
        print(json.dumps({"sealed": False, "blocking_statuses": readiness["blocking_statuses"]}, sort_keys=True))
        return 1
    seal = {
        "schema_version": 1,
        "status": "F1_SEALED",
        "sealed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "readiness_sha256": sha256_file(ROOT / "freeze" / "F1_readiness.json"),
        "dependencies": dependencies(),
        "f2_run_plan": "freeze/F2_run_plan.json",
    }
    write_json_new(ROOT / "freeze" / "F1_SEALED.json", seal)
    print(json.dumps({"sealed": True, "dependencies": len(seal["dependencies"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
