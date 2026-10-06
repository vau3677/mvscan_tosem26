#!/usr/bin/env python3
"""No-edit build screens. This invocation records evidence-backed historical blockers."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from runners.common import ROOT, write_json_new

HISTORICAL_POPULATION = ROOT / "benchmarks" / "isu" / "oracle_population.csv"
HISTORICAL_ATTEMPTS = ROOT / "benchmarks" / "isu" / "build_attempts.csv"
HISTORICAL_ATTEMPT_ARCHIVE = (
    ROOT / "benchmarks" / "isu" / "build_screen_attempts" / "initial-header-only.csv"
)
HISTORICAL_SUMMARY = ROOT / "benchmarks" / "isu" / "build_screen_summary.json"
FIELDS = [
    "attempt_id", "oracle_row_id", "revision_role", "source_repository",
    "revision", "command_evidence", "command", "toolchain_evidence", "toolchain",
    "started_at", "duration_seconds", "timeout_seconds", "exit_code",
    "terminal_status", "stdout_sha256", "stderr_sha256", "source_sha256",
    "build_sha256", "prohibited_edit_detected", "acceptance_check", "notes",
]
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def load(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def screen_historical() -> dict[str, object]:
    population = load(HISTORICAL_POPULATION)
    if len(population) != 116 or len({row["oracle_row_id"] for row in population}) != 116:
        raise RuntimeError("historical population identity failure")
    existing = load(HISTORICAL_ATTEMPTS)
    if existing:
        raise FileExistsError("refusing to overwrite historical build attempts")
    if HISTORICAL_ATTEMPT_ARCHIVE.exists() or HISTORICAL_SUMMARY.exists():
        raise FileExistsError("historical build screen has already been initialized")
    HISTORICAL_ATTEMPT_ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    os.replace(HISTORICAL_ATTEMPTS, HISTORICAL_ATTEMPT_ARCHIVE)
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    records = []
    for row in sorted(population, key=lambda item: item["oracle_row_id"]):
        repository = row.get("source_repository", "").strip()
        revision = row.get("vulnerable_revision", "").strip()
        if repository or revision:
            raise RuntimeError(
                "an explicit historical source identity exists and requires a real no-edit build attempt: "
                + row["oracle_row_id"]
            )
        records.append(
            {
                "attempt_id": row["oracle_row_id"] + "-vulnerable-source-resolution-001",
                "oracle_row_id": row["oracle_row_id"],
                "revision_role": "vulnerable",
                "source_repository": "",
                "revision": "",
                "command_evidence": (
                    "frozen artifact and report row inspected; no explicit vulnerable "
                    "repository and revision are supplied"
                ),
                "command": "",
                "toolchain_evidence": "not selected because source identity is unresolved",
                "toolchain": "",
                "started_at": timestamp,
                "duration_seconds": "0",
                "timeout_seconds": "900",
                "exit_code": "",
                "terminal_status": "UNAVAILABLE_SOURCE_VERSION",
                "stdout_sha256": EMPTY_SHA256,
                "stderr_sha256": EMPTY_SHA256,
                "source_sha256": "",
                "build_sha256": "",
                "prohibited_edit_detected": "false",
                "acceptance_check": "BLOCKED_BUILD_RECONSTRUCTION",
                "notes": (
                    "No repository or vulnerable revision may be inferred from report identity "
                    "or synthesized merely to obtain a build."
                ),
            }
        )
    with HISTORICAL_ATTEMPTS.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    summary = {
        "schema_version": 1,
        "population_rows": 116,
        "screened_rows": 116,
        "accepted_builds": 0,
        "terminal_status_counts": {"UNAVAILABLE_SOURCE_VERSION": 116},
        "f1_status": "BLOCKED_BUILD_RECONSTRUCTION",
        "decision_basis": (
            "The frozen historical artifact supplies report identities but no explicit "
            "vulnerable source repositories or revisions for all 116 rows."
        ),
        "prohibited_inference_performed": False,
    }
    write_json_new(HISTORICAL_SUMMARY, summary)
    return summary


def main() -> int:
    print(json.dumps(screen_historical(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
