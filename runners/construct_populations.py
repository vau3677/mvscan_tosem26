#!/usr/bin/env python3
from __future__ import annotations
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path
from runners.common import ROOT, sha256_file, tree_digest, write_json_new

ISU = ROOT / "benchmarks/sources/SolidityStateStudy"
WEB3 = ROOT / "benchmarks/sources/Web3Bugs"
ISU_COMMIT = "985e0032449aaa4fec4b6d2f9f7902525cbbb736"
WEB3_COMMIT = "fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4"

def write_csv_new(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)

def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def assert_checkout(repo: Path, commit: str) -> None:
    actual = git(repo, "rev-parse", "HEAD").decode().strip()
    status = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if actual != commit or status:
        raise SystemExit(f"checkout acceptance failure: {repo}: commit={actual!r}, dirty={bool(status)}")

def historical_rows() -> list[dict[str, object]]:
    root = ISU / "Inconsistent-State-Update-Vulnerabilities/Classification-by-Root-Causes"
    link = re.compile(r"\[([^]]+)\]\(([^)]+)\)")
    rows: list[dict[str, object]] = []
    for readme in sorted(root.glob("*/README.md"), key=lambda p: p.parent.name):
        category = readme.parent.name
        for raw in readme.read_text(encoding="utf-8").splitlines():
            if not re.match(r"^\|[0-9]+\|", raw):
                continue
            cells = [cell.strip() for cell in raw.strip().strip("|").split("|")]
            if len(cells) != 6:
                raise SystemExit(f"unexpected row shape: {readme}: {raw}")
            serial, reporting_time, link_cell, root_cause, exploit, fix = cells
            match = link.fullmatch(link_cell)
            if not match:
                raise SystemExit(f"unexpected report link: {link_cell}")
            report_identity, report_url = match.groups()
            identity = f"{category}\0{serial}\0{report_identity}\0{report_url}"
            rows.append({
                "oracle_row_id": "isu-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
                "root_cause_category": category, "category_serial_number": serial,
                "reporting_time": reporting_time, "report_identity": report_identity,
                "report_url": report_url, "artifact_path": readme.relative_to(ISU).as_posix(),
                "artifact_row_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "root_cause_evidence": root_cause, "exploitation_evidence": exploit,
                "fix_strategy_evidence": fix, "source_repository": "",
                "vulnerable_revision": "", "exact_fixed_revision": "",
                "affected_contract": "", "affected_function": "", "source_reference": "",
            })
    if len(rows) != 116 or len({row["oracle_row_id"] for row in rows}) != 116:
        raise SystemExit(f"population construction failure: rows={len(rows)} unique={len({row['oracle_row_id'] for row in rows})}")
    return sorted(rows, key=lambda row: str(row["oracle_row_id"]))

def historical_artifacts(rows: list[dict[str, object]]) -> None:
    write_csv_new(ROOT / "benchmarks/isu/oracle_population.csv", list(rows[0]), rows)
    tracked = [ISU / item.decode("utf-8") for item in git(ISU, "ls-files", "-z").split(b"\0") if item]
    source_rows = [{"relative_path": path.relative_to(ISU).as_posix(), "byte_size": path.stat().st_size, "sha256": sha256_file(path), "artifact_role": "frozen_historical_artifact"} for path in tracked]
    write_csv_new(ROOT / "benchmarks/isu/source_manifest.csv", ["relative_path", "byte_size", "sha256", "artifact_role"], source_rows)
    adjudication_fields = ["oracle_row_id", "annotator_1_class", "annotator_2_class", "disagreement_fields", "adjudicated_class", "adjudicator_id", "adjudication_rationale", "evidence_references", "adjudicated_at"]
    write_csv_new(ROOT / "benchmarks/isu/adjudications.csv", adjudication_fields, [])
    (ROOT / "benchmarks/isu/semantic_match_oracles.jsonl").open("x", encoding="utf-8").close()
    exposure_fields = ["oracle_row_id", "pre_freeze_exposure", "exposure_note", "reviewed_by", "reviewed_at"]
    write_csv_new(ROOT / "benchmarks/isu/exposure.csv", exposure_fields, [{"oracle_row_id": row["oracle_row_id"], "pre_freeze_exposure": "", "exposure_note": "", "reviewed_by": "", "reviewed_at": ""} for row in rows])
    build_fields = ["attempt_id", "oracle_row_id", "revision_role", "source_repository", "revision", "command_evidence", "command", "toolchain_evidence", "toolchain", "started_at", "duration_seconds", "timeout_seconds", "exit_code", "terminal_status", "stdout_sha256", "stderr_sha256", "source_sha256", "build_sha256", "prohibited_edit_detected", "acceptance_check", "notes"]
    write_csv_new(ROOT / "benchmarks/isu/build_attempts.csv", build_fields, [])
    packet_dir = ROOT / "benchmarks/isu/evidence_packets"
    packet_dir.mkdir(parents=True, exist_ok=False)
    for row in rows:
        packet = {"oracle_row_id": row["oracle_row_id"], "frozen_artifact_evidence": {key: row[key] for key in ("root_cause_category", "category_serial_number", "reporting_time", "report_identity", "report_url", "artifact_path", "artifact_row_sha256", "root_cause_evidence", "exploitation_evidence", "fix_strategy_evidence")}, "source_evidence": [], "documentation_evidence": [], "test_evidence": [], "exact_fixed_revision_evidence": []}
        write_json_new(packet_dir / f"{row['oracle_row_id']}.json", packet)

def web3_population() -> list[dict[str, object]]:
    root = WEB3 / "contracts"
    snapshots = [p for p in root.iterdir() if p.is_dir() and re.fullmatch(r"[0-9]+", p.name) and any(q.is_file() and not q.is_symlink() for q in p.rglob("*.sol"))]
    rows, scope_rows = [], []
    for snapshot in sorted(snapshots, key=lambda p: int(p.name)):
        snapshot_digest, file_count, byte_size = tree_digest(snapshot)
        solidity = sorted((p for p in snapshot.rglob("*.sol") if p.is_file() and not p.is_symlink()), key=lambda p: p.relative_to(snapshot).as_posix())
        solidity_digest, solidity_count, solidity_bytes = tree_digest(snapshot, solidity)
        rows.append({"snapshot_id": snapshot.name, "repository": "https://github.com/ZhangZhuoSJTU/Web3Bugs.git", "commit": WEB3_COMMIT, "population_path": f"contracts/{snapshot.name}", "file_count": file_count, "byte_size": byte_size, "snapshot_sha256": snapshot_digest, "solidity_file_count": solidity_count, "solidity_byte_size": solidity_bytes, "solidity_sha256": solidity_digest, "population_status": "INITIAL"})
        for path in solidity:
            scope_rows.append({"snapshot_id": snapshot.name, "source_path": path.relative_to(snapshot).as_posix(), "source_sha256": sha256_file(path), "scope": "IN_SCOPE", "scope_evidence": "unknown first-party source remains IN_SCOPE; any evidence-backed exclusion must be frozen before F1 sealing"})
    if not rows or len(rows) != len({row["snapshot_id"] for row in rows}):
        raise SystemExit("Web3Bugs population construction failure")
    write_csv_new(ROOT / "benchmarks/web3bugs/population.csv", list(rows[0]), rows)
    write_csv_new(ROOT / "benchmarks/web3bugs/source_scope.csv", ["snapshot_id", "source_path", "source_sha256", "scope", "scope_evidence"], scope_rows)
    build_fields = ["attempt_id", "snapshot_id", "command_evidence_rank", "command_evidence", "command", "toolchain_evidence", "toolchain", "started_at", "duration_seconds", "timeout_seconds", "exit_code", "terminal_status", "stdout_sha256", "stderr_sha256", "source_sha256_before", "source_sha256_after", "build_sha256", "prohibited_edit_detected", "acceptance_check", "notes"]
    write_csv_new(ROOT / "benchmarks/web3bugs/build_attempts.csv", build_fields, [])
    write_csv_new(ROOT / "benchmarks/web3bugs/accepted_cohort.csv", ["snapshot_id", "accepted_attempt_id", "command", "toolchain", "source_sha256", "build_sha256", "accepted"], [])
    return rows

def overlap(historical: list[dict[str, object]], web3: list[dict[str, object]]) -> None:
    references: dict[str, set[str]] = {}
    with (WEB3 / "results/bugs.csv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, skipinitialspace=True):
            references.setdefault(row["Reference"].strip(), set()).add(row["Contest ID"].strip())
    by_contest: dict[str, list[str]] = {}
    for row in historical:
        for contest in references.get(str(row["report_url"]), set()):
            by_contest.setdefault(contest, []).append(str(row["oracle_row_id"]))
    fields = ["snapshot_id", "benchmark_overlap", "overlap_basis", "overlapping_oracle_row_ids", "pre_freeze_exposure", "exposure_note", "reviewed_by", "reviewed_at"]
    records = []
    for snapshot in web3:
        snapshot_id = str(snapshot["snapshot_id"])
        ids = sorted(by_contest.get(snapshot_id, []))
        records.append({"snapshot_id": snapshot_id, "benchmark_overlap": "true" if ids else "false", "overlap_basis": "exact report identity" if ids else "none found by exact report identity", "overlapping_oracle_row_ids": ";".join(ids), "pre_freeze_exposure": "", "exposure_note": "", "reviewed_by": "", "reviewed_at": ""})
    write_csv_new(ROOT / "benchmarks/web3bugs/overlap_and_exposure.csv", fields, records)

def main() -> int:
    assert_checkout(ISU, ISU_COMMIT)
    assert_checkout(WEB3, WEB3_COMMIT)
    historical = historical_rows()
    historical_artifacts(historical)
    web3 = web3_population()
    overlap(historical, web3)
    print(json.dumps({"historical_population": len(historical), "web3bugs_initial_population": len(web3)}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
