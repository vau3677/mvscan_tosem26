#!/usr/bin/env python3
"""Fail-closed validation for one MV-Scan run; safe synthetic inputs are testable."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from runners.artifact_storage import read_json
from runners.configuration import detector_effective_config, load_named

EXPECTED_DETECTOR_HASHES = {
    "inconsistent_state": "83999325fe57207d770a02bfb61a0a4389a5d1faeab4a1360d2975aef438c14c",
    "icfg": "4c26fe2f758da22c1f9710ccd58681e59c687ab2a793fe292d453ca97c0f742b",
    "mvscan_env": "dd9b7bd80f859c91d7820cb2502b7f79027a40938b6a57f4bbee9ea54bcdc176",
}
MODELED_SINK_KINDS = {"control", "storage_write", "external_effect"}


class ValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def structural_digest(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalized(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_candidate(candidate: dict[str, Any], location: str) -> tuple[int, int]:
    require(isinstance(candidate.get("candidate_id"), str) and candidate["candidate_id"], f"{location}: invalid candidate_id")
    relation = candidate.get("relation")
    require(isinstance(relation, dict), f"{location}: relation must be an object")
    members = relation.get("members")
    require(isinstance(members, list) and len(members) >= 2, f"{location}: relation arity must be at least two")
    member_keys = []
    for index, member in enumerate(members):
        require(isinstance(member, dict) and "entity_key" in member, f"{location}: member {index} lacks entity_key")
        member_keys.append(normalized(member["entity_key"]))
    require(len(member_keys) == len(set(member_keys)), f"{location}: duplicate relation entity_key")

    written_raw = candidate.get("written_members")
    omitted_raw = candidate.get("potentially_stale_members")
    require(isinstance(written_raw, list) and written_raw, f"{location}: written_members must be nonempty")
    require(isinstance(omitted_raw, list), f"{location}: potentially_stale_members must be a list")
    written = {normalized(value) for value in written_raw}
    omitted = {normalized(value) for value in omitted_raw}
    relation_set = set(member_keys)
    require(written < relation_set, f"{location}: written_members must be a proper relation subset")
    require(omitted == relation_set - written, f"{location}: omitted members must equal the relation complement")

    contexts = candidate.get("context_instances")
    witnesses = candidate.get("reader_witnesses")
    require(isinstance(contexts, list), f"{location}: context_instances must be a list")
    require(isinstance(witnesses, list) and witnesses, f"{location}: reader_witnesses must be nonempty")
    require(candidate.get("context_instance_count") == len(contexts), f"{location}: context_instance_count mismatch")
    require(candidate.get("reader_witness_count") == len(witnesses), f"{location}: reader_witness_count mismatch")
    for witness_index, witness in enumerate(witnesses):
        witness_location = f"{location}.reader_witnesses[{witness_index}]"
        require(isinstance(witness, dict), f"{witness_location}: witness must be an object")
        evidence = witness.get("relation_evidence")
        sinks = witness.get("sinks")
        require(isinstance(evidence, list) and evidence, f"{witness_location}: relation_evidence must be nonempty")
        require(isinstance(sinks, list) and sinks, f"{witness_location}: sinks must be nonempty")
        for edge_index, edge in enumerate(evidence):
            edge_location = f"{witness_location}.relation_evidence[{edge_index}]"
            require(isinstance(edge, dict), f"{edge_location}: evidence must be an object")
            writer_member = edge.get("writer_member")
            reader_member = edge.get("reader_member")
            require(isinstance(writer_member, dict) and "entity_key" in writer_member, f"{edge_location}: writer member lacks entity_key")
            require(isinstance(reader_member, dict) and "entity_key" in reader_member, f"{edge_location}: reader member lacks entity_key")
            writer_key = normalized(writer_member["entity_key"])
            reader_key = normalized(reader_member["entity_key"])
            require(writer_key in written, f"{edge_location}: writer is not a written relation member")
            require(reader_key in omitted, f"{edge_location}: reader is not an omitted relation member")
            require(writer_key != reader_key, f"{edge_location}: writer and reader members must differ")
        for sink_index, sink in enumerate(sinks):
            sink_location = f"{witness_location}.sinks[{sink_index}]"
            require(
                isinstance(sink, dict) and sink.get("kind") in MODELED_SINK_KINDS,
                f"{sink_location}: unsupported modeled sink",
            )
    return len(contexts), len(witnesses)


def validate_document(
    document: dict[str, Any],
    expected_effective_config: dict[str, Any],
    expected_compilation_units: dict[str, dict[str, Any]] | None = None,
    expected_detector_hashes: dict[str, str] = EXPECTED_DETECTOR_HASHES,
) -> dict[str, int]:
    require(isinstance(document, dict), "document must be an object")
    detector = document.get("detector")
    require(isinstance(detector, dict), "detector metadata must be an object")
    require(detector.get("name") == "MV-Scan", "detector name mismatch")
    require(detector.get("source_hashes") == expected_detector_hashes, "detector source hashes mismatch")
    require(document.get("effective_config") == expected_effective_config, "effective_config mismatch")
    units = document.get("compilation_units")
    require(isinstance(units, list), "compilation_units must be a list")
    unit_ids = [unit.get("unit_id") for unit in units if isinstance(unit, dict)]
    require(len(unit_ids) == len(units) and all(isinstance(value, str) and value for value in unit_ids), "invalid compilation-unit ID")
    require(len(unit_ids) == len(set(unit_ids)), "compilation-unit IDs must be unique")
    if expected_compilation_units is not None:
        require(set(unit_ids) == set(expected_compilation_units), "compilation-unit identity mismatch")

    aggregate_candidates = aggregate_contexts = aggregate_witnesses = 0
    for unit_index, unit in enumerate(units):
        location = f"compilation_units[{unit_index}]"
        candidates = unit.get("candidates")
        require(isinstance(candidates, list), f"{location}: candidates must be a list")
        candidate_ids = [
            candidate.get("candidate_id") for candidate in candidates if isinstance(candidate, dict)
        ]
        require(len(candidate_ids) == len(candidates), f"{location}: malformed candidate")
        require(len(candidate_ids) == len(set(candidate_ids)), f"{location}: candidate IDs must be unique")
        unit_contexts = unit_witnesses = 0
        for candidate_index, candidate in enumerate(candidates):
            contexts, witnesses = validate_candidate(
                candidate, f"{location}.candidates[{candidate_index}]"
            )
            unit_contexts += contexts
            unit_witnesses += witnesses
        require(unit.get("candidate_count") == len(candidates), f"{location}: candidate_count mismatch")
        require(unit.get("context_instance_count") == unit_contexts, f"{location}: context aggregate mismatch")
        require(unit.get("reader_witness_count") == unit_witnesses, f"{location}: witness aggregate mismatch")
        stats = unit.get("stats")
        require(isinstance(stats, dict), f"{location}: stats must be an object")
        require(stats.get("candidate_count") == len(candidates), f"{location}: stats candidate_count mismatch")
        require(stats.get("context_instance_count") == unit_contexts, f"{location}: stats context count mismatch")
        require(stats.get("reader_witness_count") == unit_witnesses, f"{location}: stats witness count mismatch")
        require(stats.get("candidate_digest") == structural_digest(candidates), f"{location}: candidate digest mismatch")
        metadata = unit.get("compilation_metadata")
        require(isinstance(metadata, dict), f"{location}: compilation_metadata must be an object")
        if expected_compilation_units is not None:
            expected = expected_compilation_units[unit["unit_id"]]
            for key in (
                "solidity_compiler_version",
                "target_source_digest",
                "build_info_digest",
            ):
                require(metadata.get(key) == expected.get(key), f"{location}: {key} mismatch")
        aggregate_candidates += len(candidates)
        aggregate_contexts += unit_contexts
        aggregate_witnesses += unit_witnesses

    require(document.get("candidate_count") == aggregate_candidates, "document candidate_count mismatch")
    require(document.get("context_instance_count") == aggregate_contexts, "document context count mismatch")
    require(document.get("reader_witness_count") == aggregate_witnesses, "document witness count mismatch")
    return {
        "candidate_count": aggregate_candidates,
        "compilation_unit_count": len(units),
        "context_instance_count": aggregate_contexts,
        "reader_witness_count": aggregate_witnesses,
    }


def validate_run(
    run_directory: Path,
    manifest: dict[str, Any] | None = None,
) -> dict[str, int]:
    if manifest is None:
        manifest_path = run_directory / "run_manifest.json"
        require(manifest_path.is_file(), "run manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "run manifest must be an object")
    require(manifest.get("terminal_status") == "SUCCESS", "run terminal status is not SUCCESS")
    require(manifest.get("process_exit_code") == 0, "detector process exit is nonzero")
    require(not manifest.get("timed_out"), "run timed out")
    require(not manifest.get("oom_killed"), "run was OOM-killed")
    require(not manifest.get("context_bound_failure"), "run had a context-bound failure")
    for key in (
        "source_snapshot_sha256",
        "build_sha256",
        "compiler_sha256",
        "environment_digest",
    ):
        require(
            manifest.get("actual_inputs", {}).get(key)
            == manifest.get("expected_inputs", {}).get(key),
            f"runner {key} mismatch",
        )
    output = run_directory / manifest.get("detector_json", "detector.json")
    require(output.is_file(), "expected detector JSON is missing")
    partials = list(output.parent.glob(output.name + ".tmp.*"))
    require(not partials, "partial detector output remains")
    try:
        document = read_json(output)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise ValidationError(f"detector JSON does not parse completely: {exc}") from exc
    expected_units = manifest.get("expected_compilation_units")
    require(isinstance(expected_units, dict), "expected compilation-unit metadata is missing")
    configuration = manifest.get("configuration")
    expected_effective = detector_effective_config(load_named(configuration))
    return validate_document(document, expected_effective, expected_units)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    try:
        summary = validate_run(args.run_directory.resolve())
    except ValidationError as exc:
        print(json.dumps({"status": "BLOCKED_VALIDATION", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "COMPLETE", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
