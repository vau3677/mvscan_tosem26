#!/usr/bin/env python3
"""Build the frozen cross-ablation structural-candidate union."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from runners.artifact_storage import read_json
from runners.common import ROOT, canonical_bytes
from runners.configuration import CONFIG_NAMES


SCHEMA_VERSION = 2
OUT_OF_SCOPE_COMPONENTS = {
    "test", "tests", "testing", "mock", "mocks", "fixture", "fixtures",
    "harness", "harnesses", "example", "examples",
    "deps", "dependencies", "vendor", "vendors", "lib", "libs",
}
OUT_OF_SCOPE_BASENAME = re.compile(r"(?:mock|harness|test)\.sol$", re.IGNORECASE)


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sorted_unique(values: list[Any]) -> list[Any]:
    keyed = {canonical(value): value for value in values}
    return [keyed[key] for key in sorted(keyed)]


def structural_payload(
    manifest: dict[str, Any],
    candidate: dict[str, Any],
    in_scope_origins: list[dict[str, Any]],
    in_scope_witnesses: list[dict[str, Any]],
) -> dict[str, Any]:
    relation = candidate.get("relation")
    members = relation.get("members") if isinstance(relation, dict) else None
    writer_block = candidate.get("writer_block")
    if not isinstance(members, list) or len(members) < 2:
        raise ValueError("candidate relation is missing or unary")
    if not isinstance(writer_block, dict):
        raise ValueError("candidate writer block is missing")
    entity_keys = []
    entity_kinds = []
    for member in members:
        if not isinstance(member, dict) or "entity_key" not in member or "kind" not in member:
            raise ValueError("relation member lacks entity identity")
        entity_keys.append(member["entity_key"])
        entity_kinds.append(member["kind"])
    owners = [candidate.get("writer_owner")]
    witness_keys = []
    sink_kinds = []
    for witness in in_scope_witnesses:
        reader = witness.get("reader", {})
        writer = witness.get("writer", {})
        reader_context = reader.get("context", {})
        writer_context = writer.get("context", {})
        owners.extend([writer_context.get("owner"), reader_context.get("owner")])
        sink_keys = []
        for sink in witness.get("sinks", []):
            sink_kinds.append(sink.get("kind"))
            sink_keys.append({
                "function_key": sink.get("function_key"),
                "node_id": sink.get("node_id"),
                "kind": sink.get("kind"),
            })
        witness_keys.append({
            "reader": {
                "file": reader.get("file"),
                "line": reader.get("line"),
                "signature": reader.get("signature"),
                "block": reader.get("block"),
                "owner": reader_context.get("owner"),
                "storage_context": reader_context.get("storage_context"),
            },
            "writer_owner": writer_context.get("owner"),
            "sinks": sorted_unique(sink_keys),
            "relation_evidence": sorted_unique(witness.get("relation_evidence", [])),
        })
    if any(not isinstance(value, str) or not value for value in owners):
        raise ValueError("transaction-context owner is missing")
    if any(not isinstance(value, str) or not value for value in sink_kinds):
        raise ValueError("sink kind is missing")
    for key in ("dataset", "subject", "revision_role"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            raise ValueError(f"manifest {key} is missing")
    for key in ("function_key", "node_id"):
        if key not in writer_block:
            raise ValueError(f"writer block {key} is missing")
    return {
        "schema_version": SCHEMA_VERSION,
        "dataset": manifest["dataset"],
        "subject": manifest["subject"],
        "revision_role": manifest["revision_role"],
        "writer_owner": candidate.get("writer_owner"),
        "writer_block": {
            "function_key": writer_block["function_key"],
            "node_id": writer_block["node_id"],
        },
        "relation_members": sorted_unique(entity_keys),
        "written_members": sorted_unique(candidate.get("written_members", [])),
        "potentially_stale_members": sorted_unique(candidate.get("potentially_stale_members", [])),
        "transaction_context_owners": sorted(set(owners)),
        "sink_kinds": sorted(set(sink_kinds)),
        "origin_sites": sorted_unique([
            {
                "function_key": origin.get("function_key"),
                "block_id": origin.get("block_id"),
                "expression": origin.get("expression"),
            }
            for origin in in_scope_origins
        ]),
        "witness_sites": sorted_unique(witness_keys),
        "key_equality_constraints": sorted_unique(candidate.get("key_equality_constraints", [])),
        "shape_tags": {
            "relation_arity": len(entity_keys),
            "entity_kinds": sorted(entity_kinds),
        },
    }


def global_candidate_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def successful_primary_manifests(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    result = []
    for path in sorted((root / "runs").glob("*/run_manifest.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if (
            document.get("dataset") != "web3bugs"
            or document.get("python_hash_seed") != 0
            or document.get("terminal_status") != "SUCCESS"
        ):
            continue
        if document.get("configuration") not in CONFIG_NAMES:
            raise ValueError(f"unknown configuration in {path}")
        result.append((path, document))
    return result


def load_source_scope(root: Path) -> dict[tuple[str, str], str]:
    result = {}
    with (root / "benchmarks/web3bugs/source_scope.csv").open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            key = (str(row["snapshot_id"]), row["source_path"].removeprefix("./"))
            if key in result:
                raise ValueError(f"duplicate source-scope row: {key}")
            result[key] = row["scope"]
    return result


def resolve_source_scope(
    subject: str,
    path: Any,
    source_scope: dict[tuple[str, str], str],
) -> str:
    """Resolve compiler-root paths against checkout-root paths in the frozen table."""
    if not isinstance(path, str) or not path:
        return "MISSING"
    normalized = path.removeprefix("./")
    parts = [part.lower() for part in normalized.split("/")]
    if (
        normalized.startswith("node_modules/")
        or normalized.startswith("@")
        or any(part in OUT_OF_SCOPE_COMPONENTS for part in parts[:-1])
        or OUT_OF_SCOPE_BASENAME.search(parts[-1])
    ):
        return "OUT_OF_SCOPE"
    exact = source_scope.get((subject, normalized))
    if exact is not None:
        return exact
    suffix_statuses = {
        status
        for (snapshot_id, frozen_path), status in source_scope.items()
        if snapshot_id == subject and frozen_path.endswith("/" + normalized)
    }
    if len(suffix_statuses) == 1:
        return suffix_statuses.pop()
    # The protocol explicitly keeps unmatched first-party source in scope.
    return "IN_SCOPE"


def function_source(function_key: Any) -> str | None:
    if not isinstance(function_key, str) or "::" not in function_key:
        return None
    return function_key.split("::", 1)[0].removeprefix("./")


def candidate_frame(
    subject: str,
    candidate: dict[str, Any],
    source_scope: dict[tuple[str, str], str],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    def scope(path: Any) -> str:
        return resolve_source_scope(subject, path, source_scope)

    writer = candidate.get("writer_block")
    writer_scope = scope(writer.get("file") if isinstance(writer, dict) else None)
    origins = candidate.get("supporting_origin_sites")
    witnesses = candidate.get("reader_witnesses")
    if writer_scope in {"UNKNOWN", "MISSING"}:
        return "UNKNOWN_WRITER_SCOPE", [], []
    if writer_scope != "IN_SCOPE":
        return "OUT_OF_SCOPE_WRITER", [], []
    relation = candidate.get("relation")
    members = relation.get("members") if isinstance(relation, dict) else None
    if not isinstance(members, list):
        return "MISSING_RELATION_MEMBERS", [], []
    member_scopes = []
    for member in members:
        key = member.get("entity_key") if isinstance(member, dict) else None
        member_scopes.append(scope(key[1] if isinstance(key, list) and len(key) > 1 else None))
    if any(value in {"UNKNOWN", "MISSING"} for value in member_scopes):
        return "UNKNOWN_RELATION_MEMBER_SCOPE", [], []
    if any(value != "IN_SCOPE" for value in member_scopes):
        return "OUT_OF_SCOPE_RELATION_MEMBER", [], []
    if not isinstance(origins, list):
        return "MISSING_ORIGINS", [], []
    origin_pairs = [(origin, scope(function_source(origin.get("function_key")))) for origin in origins if isinstance(origin, dict)]
    origin_scopes = [value for _, value in origin_pairs]
    if any(value in {"UNKNOWN", "MISSING"} for value in origin_scopes):
        return "UNKNOWN_ORIGIN_SCOPE", [], []
    in_scope_origins = [origin for origin, value in origin_pairs if value == "IN_SCOPE"]
    if not in_scope_origins:
        return "NO_IN_SCOPE_ORIGIN", [], []
    if not isinstance(witnesses, list):
        return "MISSING_WITNESSES", [], []
    unknown_witness_scope = False
    in_scope_witnesses = []
    for witness in witnesses:
        if not isinstance(witness, dict):
            continue
        reader = witness.get("reader")
        reader_scope = scope(reader.get("file") if isinstance(reader, dict) else None)
        sinks = witness.get("sinks")
        sink_scopes = (
            [
                scope(function_source(sink.get("function_key")))
                for sink in sinks if isinstance(sink, dict)
            ]
            if isinstance(sinks, list)
            else []
        )
        unknown_witness_scope |= reader_scope in {"UNKNOWN", "MISSING"} or any(
            value in {"UNKNOWN", "MISSING"} for value in sink_scopes
        )
        if reader_scope == "IN_SCOPE" and "IN_SCOPE" in sink_scopes:
            retained = dict(witness)
            retained["sinks"] = [
                sink for sink, value in zip(sinks, sink_scopes) if value == "IN_SCOPE"
            ]
            in_scope_witnesses.append(retained)
    if in_scope_witnesses:
        return "IN_SCOPE", in_scope_origins, in_scope_witnesses
    return ("UNKNOWN_WITNESS_SCOPE" if unknown_witness_scope else "NO_IN_SCOPE_READER_AND_SINK"), [], []


def candidate_frame_status(
    subject: str,
    candidate: dict[str, Any],
    source_scope: dict[tuple[str, str], str],
) -> str:
    return candidate_frame(subject, candidate, source_scope)[0]


def build(root: Path = ROOT, source_scope_path: Path | None = None) -> dict[str, Any]:
    buckets: dict[str, dict[str, Any]] = {}
    native_counts: Counter[str] = Counter()
    frame_counts: Counter[str] = Counter()
    if source_scope_path is None:
        source_scope = load_source_scope(root)
    else:
        source_scope = {}
        with source_scope_path.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                source_scope[(str(row["snapshot_id"]), row["source_path"].removeprefix("./"))] = row["scope"]
    manifests = successful_primary_manifests(root)
    for manifest_path, manifest in manifests:
        output = manifest_path.parent / str(manifest.get("detector_json", "detector.json"))
        document = read_json(output)
        configuration = str(manifest["configuration"])
        for unit in document.get("compilation_units", []):
            unit_id = unit.get("unit_id")
            for candidate in unit.get("candidates", []):
                native_counts[configuration] += 1
                frame_status, origins, witnesses = candidate_frame(str(manifest["subject"]), candidate, source_scope)
                frame_counts[f"{configuration}:{frame_status}"] += 1
                if frame_status.startswith("UNKNOWN") or frame_status.startswith("MISSING"):
                    raise ValueError(
                        f"unresolved frozen source scope for {manifest['run_id']} "
                        f"candidate {candidate.get('candidate_id')}: {frame_status}"
                    )
                if frame_status != "IN_SCOPE":
                    continue
                payload = structural_payload(manifest, candidate, origins, witnesses)
                identity = global_candidate_id(payload)
                bucket = buckets.setdefault(identity, {
                    "global_candidate_id": identity,
                    "structural_payload": payload,
                    "configurations": [],
                    "source_candidates": [],
                })
                if bucket["structural_payload"] != payload:
                    raise RuntimeError("SHA-256 structural collision")
                bucket["configurations"].append(configuration)
                bucket["source_candidates"].append({
                    "configuration": configuration,
                    "run_id": manifest["run_id"],
                    "compilation_unit_id": unit_id,
                    "candidate_id": candidate.get("candidate_id"),
                })
    membership_counts: Counter[str] = Counter()
    for bucket in buckets.values():
        configurations = sorted(set(bucket["configurations"]))
        if len(configurations) != len(bucket["configurations"]):
            raise ValueError("duplicate structural bucket within one configuration/subject")
        bucket["configurations"] = configurations
        bucket["source_candidates"] = sorted(
            bucket["source_candidates"],
            key=lambda row: (row["configuration"], row["run_id"], str(row["compilation_unit_id"]), str(row["candidate_id"])),
        )
        membership_counts["+".join(configurations)] += 1
    ordered = [buckets[key] for key in sorted(buckets)]
    return {
        "schema_version": SCHEMA_VERSION,
        "population": "successful seed-0 cross-ablation structural union",
        "configurations": list(CONFIG_NAMES),
        "successful_primary_manifests": len(manifests),
        "native_candidate_counts": dict(sorted(native_counts.items())),
        "candidate_frame_counts": dict(sorted(frame_counts.items())),
        "union_bucket_count": len(ordered),
        "membership_pattern_counts": dict(sorted(membership_counts.items())),
        "buckets": ordered,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-scope", type=Path)
    args = parser.parse_args()
    result = build(source_scope_path=args.source_scope)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("successful_primary_manifests", "native_candidate_counts", "candidate_frame_counts", "union_bucket_count", "membership_pattern_counts")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
