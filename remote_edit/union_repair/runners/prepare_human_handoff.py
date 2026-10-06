#!/usr/bin/env python3
"""Create source-grounded, configuration-blind human-review materials."""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
from pathlib import Path
from typing import Any

from runners.artifact_storage import read_json
from runners.build_candidate_union import candidate_frame
from runners.common import ROOT, canonical_bytes, sha256_file
from runners.select_samples import select_configurations

WEB3_FIELDS = ["review_id", "global_candidate_id", "subject", "packet", "label",
               "nonbug_primary_cause", "C1", "C2", "C3", "C4", "C5",
               "confidence", "evidence_notes"]
ISU_FIELDS = ["review_id", "oracle_row_id", "evidence_packet", "semantic_class",
              "C1", "C2", "C3", "C4", "C5", "confidence", "evidence_notes"]
SOURCE_INDEX: dict[tuple[Path, str], list[tuple[str, Path]]] = {}
START_TEXT = """# Human Review: Start Here

Use only the sheet assigned to you and the packet named in each row. Do not inspect `freeze/`, detector configurations, another reviewer's sheet, or administrative selection files.

| Assignment | Sheet | Guide |
| --- | --- | --- |
| Web3Bugs primary | `web3bugs_primary.csv` | `WEB3BUGS_GUIDE.md` |
| Web3Bugs agreement | `web3bugs_agreement.csv` | `WEB3BUGS_GUIDE.md` |
| ISU reviewer 1 | `isu_reviewer_1.csv` | `ISU_GUIDE.md` |
| ISU reviewer 2 | `isu_reviewer_2.csv` | `ISU_GUIDE.md` |

For each row, open the JSON path in `packet` or `evidence_packet`, complete all required fields, and add a short evidence note. The agreement reviewer and the two ISU reviewers work independently.

ISU reviewers classify only the published finding shown in the packet; they do not inspect detector output. After ISU adjudication, the research team runs `runners/prepare_isu_strict_match.py` to create the separate B0 matching task for findings adjudicated as `MV_SI`.

If the supplied evidence cannot support a decision, use `INSUFFICIENT_EVIDENCE` and state exactly what is missing. Do not search the administrative tree for additional clues.
"""


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_csv(path: Path, fields: list[str], values: list[dict[str, Any]]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(values)


def load_scope(path: Path) -> dict[tuple[str, str], str]:
    return {(row["snapshot_id"], row["source_path"].removeprefix("./")): row["scope"] for row in rows(path)}


def locate(root: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative:
        return None
    normalized = relative.removeprefix("./")
    direct = root / normalized
    try:
        if direct.is_file():
            return direct
    except OSError:
        return None
    suffix = Path(normalized).suffix
    index_key = (root, suffix)
    if index_key not in SOURCE_INDEX:
        SOURCE_INDEX[index_key] = [
            (candidate.relative_to(root).as_posix(), candidate)
            for candidate in root.rglob(f"*{suffix}")
            if candidate.is_file() and not any(
                part in {"artifacts", "build", "cache", "node_modules"} for part in candidate.parts
            )
        ]
    matches = [candidate for rel, candidate in SOURCE_INDEX[index_key] if rel.endswith(normalized)]
    return matches[0] if len(matches) == 1 else None


def excerpt(root: Path, file: Any, line: Any, radius: int = 8) -> dict[str, Any]:
    path = locate(root, file)
    result = {"file": file, "line": line}
    if path is None or not isinstance(line, int):
        return {**result, "status": "SOURCE_UNAVAILABLE", "source": ""}
    source = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, line - radius), min(len(source), line + radius)
    return {**result, "status": "AVAILABLE", "resolved_path": path.relative_to(root).as_posix(),
            "start_line": lo, "end_line": hi,
            "source": "\n".join(f"{number:>6} | {source[number-1]}" for number in range(lo, hi + 1))}


def accepted_workspaces(root: Path) -> dict[str, Path]:
    result = {}
    for row in rows(root / "benchmarks/web3bugs/accepted_cohort.csv"):
        if row.get("accepted", "").lower() != "true":
            continue
        attempt = row["accepted_attempt_id"]
        result[row["snapshot_id"]] = root / "benchmarks/web3bugs/best_effort_build_runs" / row["snapshot_id"] / attempt / "workspace"
    return result


def find_candidate(document: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    for unit in document.get("compilation_units", []):
        if unit.get("unit_id") == ref["compilation_unit_id"]:
            for candidate in unit.get("candidates", []):
                if candidate.get("candidate_id") == ref["candidate_id"]:
                    return candidate
    raise RuntimeError(f"candidate provenance failed: {ref}")


def web3_handoff(root: Path, stage: Path, inventory_path: Path, scope_path: Path,
                 admin_output: Path) -> dict[str, Any]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    by_id = {bucket["global_candidate_id"]: bucket for bucket in inventory["buckets"]}
    populations = {name: [] for name in inventory["configurations"]}
    for bucket in inventory["buckets"]:
        for name in bucket["configurations"]:
            populations[name].append(bucket["global_candidate_id"])
    selection = select_configurations(populations)
    manifests = {}
    for path in (root / "runs").glob("*/run_manifest.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifests[manifest["run_id"]] = (path, manifest)
    workspaces = accepted_workspaces(root)
    scope = load_scope(scope_path)
    packet_dir = stage / "web3bugs_packets"
    packet_dir.mkdir()
    review_rows = []
    unavailable = 0
    representative_counts: dict[str, int] = {}
    tasks = []
    for number, identity in enumerate(selection["unique_primary"], 1):
        bucket = by_id[identity]
        refs = sorted(bucket["source_candidates"], key=lambda ref: (
            ref["configuration"] != "B0", ref["configuration"], ref["run_id"],
            str(ref["compilation_unit_id"]), str(ref["candidate_id"])))
        tasks.append((refs[0]["run_id"], number, identity, bucket, refs[0]))
    current_run, document = None, None
    for run_id, number, identity, bucket, ref in sorted(tasks):
        representative_counts[ref["configuration"]] = representative_counts.get(ref["configuration"], 0) + 1
        manifest_path, manifest = manifests[ref["run_id"]]
        if run_id != current_run:
            document = read_json(manifest_path.parent / manifest["detector_json"])
            current_run = run_id
        candidate = find_candidate(document, ref)
        status, origins, witnesses = candidate_frame(str(manifest["subject"]), candidate, scope)
        if status != "IN_SCOPE":
            raise RuntimeError(f"selected candidate no longer in frame: {identity}: {status}")
        workspace = workspaces.get(str(manifest["subject"]))
        if workspace is None:
            raise RuntimeError(f"accepted workspace missing for {manifest['subject']}")
        sites = [candidate.get("writer_block", {})]
        sites.extend(witness.get("reader", {}) for witness in witnesses)
        source_excerpts, seen = [], set()
        for site in sites:
            key = (site.get("file"), site.get("line")) if isinstance(site, dict) else (None, None)
            if key in seen:
                continue
            seen.add(key)
            item = excerpt(workspace, *key)
            unavailable += item["status"] != "AVAILABLE"
            source_excerpts.append(item)
            if len(source_excerpts) >= 12:
                break
        packet = {
            "schema_version": 2, "review_id": f"W3B-{number:04d}",
            "global_candidate_id": identity, "subject": bucket["structural_payload"]["subject"],
            "structural_claim": bucket["structural_payload"],
            "relation": candidate.get("relation"), "written_members": candidate.get("written_members"),
            "potentially_stale_members": candidate.get("potentially_stale_members"),
            "writer_block": candidate.get("writer_block"), "writer_owner": candidate.get("writer_owner"),
            "supporting_origin_sites": origins, "reader_witnesses": witnesses,
            "source_excerpts": source_excerpts,
        }
        packet_path = packet_dir / f"{packet['review_id']}.json"
        packet_path.write_bytes(canonical_bytes(packet) + b"\n")
        review_rows.append({"review_id": packet["review_id"], "global_candidate_id": identity,
                            "subject": packet["subject"], "packet": f"web3bugs_packets/{packet_path.name}"})
    review_rows.sort(key=lambda row: row["review_id"])
    write_csv(stage / "web3bugs_primary.csv", WEB3_FIELDS, review_rows)
    agreement = set(selection["agreement"])
    write_csv(stage / "web3bugs_agreement.csv", WEB3_FIELDS,
              [row for row in review_rows if row["global_candidate_id"] in agreement])
    overlap_subjects = {row["snapshot_id"] for row in rows(root / "benchmarks/web3bugs/overlap_and_exposure.csv")
                        if row["benchmark_overlap"].lower() == "true"}
    overlap_union = {identity for identity, bucket in by_id.items()
                     if str(bucket["structural_payload"]["subject"]) in overlap_subjects}
    admin = {"schema_version": 2, "inventory_sha256": sha256_file(inventory_path),
             "population_counts": {name: len(values) for name, values in populations.items()},
             "nonoverlap_population_counts": {name: sum(identity not in overlap_union for identity in values)
                                               for name, values in populations.items()},
             "overlap_subject_count": len(overlap_subjects),
             "overlap_union_bucket_count": len(overlap_union),
             "overlap_selected_bucket_count": sum(identity in overlap_union for identity in selection["unique_primary"]),
             "selection": selection, "representative_configuration_counts": representative_counts,
             "source_excerpt_unavailable_count": unavailable}
    admin_output.parent.mkdir(parents=True, exist_ok=True)
    with admin_output.open("x", encoding="utf-8") as stream:
        stream.write(canonical_bytes(admin).decode("utf-8") + "\n")
    return {"primary": len(review_rows), "agreement": len(agreement), "unavailable": unavailable}


def parse_json_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
        return [str(item) for item in parsed] if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def source_paths(*values: str) -> list[str]:
    found = []
    for value in values:
        for item in parse_json_list(value) or [value]:
            blob = re.search(r"/blob/[^/]+/([^#?]+)", item)
            matches = [blob.group(1)] if blob else re.findall(
                r"(?:[A-Za-z0-9_.@-]+/)*[A-Za-z0-9_.@-]+\.(?:sol|rs|vy)", item)
            for match in matches:
                normalized = match.removeprefix("./")
                if normalized not in found:
                    found.append(normalized)
    return found


def isu_source_excerpt(source_root: Path, relative: str, keywords: list[str]) -> dict[str, Any]:
    path = locate(source_root, relative)
    if path is None:
        return {"file": relative, "status": "SOURCE_UNAVAILABLE", "source": ""}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    needle = next((word for word in keywords if len(word) >= 4 and re.search(re.escape(word), "\n".join(lines), re.I)), None)
    index = next((i for i, line in enumerate(lines) if needle and re.search(re.escape(needle), line, re.I)), 0)
    lo, hi = max(1, index + 1 - 20), min(len(lines), index + 1 + 40)
    return {"file": relative, "status": "AVAILABLE", "resolved_path": path.relative_to(source_root).as_posix(),
            "start_line": lo, "end_line": hi,
            "source": "\n".join(f"{number:>6} | {lines[number-1]}" for number in range(lo, hi + 1))}


def isu_handoff(root: Path, stage: Path) -> dict[str, Any]:
    population = {row["oracle_row_id"]: row for row in rows(root / "benchmarks/isu/oracle_population.csv")}
    resolution = {row["oracle_row_id"]: row for row in rows(root / "benchmarks/isu/source_resolution.csv")}
    mapping = {row["oracle_row_id"]: row for row in rows(root / "benchmarks/isu/execution_subject_map.csv")}
    coverage = {row["oracle_row_id"]: row for row in rows(root / "benchmarks/isu/oracle_build_coverage.csv")}
    packet_dir = stage / "isu_packets"
    packet_dir.mkdir()
    review_rows = []
    grounded = 0
    for number, oracle_id in enumerate(sorted(population), 1):
        finding, resolved = population[oracle_id], resolution[oracle_id]
        source_id = mapping.get(oracle_id, {}).get("source_id") or coverage.get(oracle_id, {}).get("source_id", "")
        affected = source_paths(resolved.get("affected_source_paths", ""),
                                resolved.get("explicit_blob_links", ""),
                                resolved.get("source_reference", ""))
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", " ".join([
            finding.get("affected_function", ""), finding.get("root_cause_evidence", ""),
            finding.get("fix_strategy_evidence", "")]))
        excerpts = [isu_source_excerpt(root / "benchmarks/isu/sources" / source_id, path, words) for path in affected] if source_id else []
        grounded += any(item["status"] == "AVAILABLE" for item in excerpts)
        packet = {"schema_version": 2, "review_id": f"ISU-{number:03d}", "oracle_row_id": oracle_id,
                  "report_identity": finding["report_identity"], "report_url": finding["report_url"],
                  "published_evidence": {key: finding.get(key, "") for key in (
                      "root_cause_category", "root_cause_evidence", "exploitation_evidence", "fix_strategy_evidence")},
                  "source_resolution": {"status": resolved["resolution_status"],
                      "repository": resolved["source_repository"], "vulnerable_revision": resolved["vulnerable_revision"],
                      "affected_source_paths": affected, "build_coverage": coverage.get(oracle_id, {}).get("build_coverage", "")},
                  "source_excerpts": excerpts}
        packet_path = packet_dir / f"{oracle_id}.json"
        packet_path.write_bytes(canonical_bytes(packet) + b"\n")
        review_rows.append({"review_id": packet["review_id"], "oracle_row_id": oracle_id,
                            "evidence_packet": f"isu_packets/{packet_path.name}"})
    write_csv(stage / "isu_reviewer_1.csv", ISU_FIELDS, review_rows)
    write_csv(stage / "isu_reviewer_2.csv", ISU_FIELDS, review_rows)
    return {"findings": len(review_rows), "source_grounded": grounded}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-scope", type=Path, default=ROOT / "benchmarks/web3bugs/source_scope.csv")
    parser.add_argument("--admin-output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"output already exists: {args.output}")
    stage = args.output.with_name(args.output.name + ".tmp")
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    web3 = web3_handoff(ROOT, stage, args.inventory, args.source_scope, args.admin_output)
    isu = isu_handoff(ROOT, stage)
    shutil.copyfile(ROOT / "protocol/annotation_guide.md", stage / "ISU_GUIDE.md")
    shutil.copyfile(ROOT / "protocol/WEB3BUGS_REVIEW_GUIDE.md", stage / "WEB3BUGS_GUIDE.md")
    (stage / "START_HERE.md").write_text(START_TEXT, encoding="utf-8", newline="\n")
    files = [{"path": path.relative_to(stage).as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
             for path in sorted(stage.rglob("*")) if path.is_file()]
    manifest = {"schema_version": 2, "status": "CURRENT_HUMAN_HANDOFF", "web3bugs": web3, "isu": isu, "files": files}
    (stage / "MANIFEST.json").write_bytes(canonical_bytes(manifest) + b"\n")
    stage.rename(args.output)
    print(json.dumps({"web3bugs": web3, "isu": isu}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
