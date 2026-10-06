#!/usr/bin/env python3
"""Guarded F2 launcher; refuses all work unless the complete F1 seal remains valid."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from runners.common import ROOT, sha256_file
from runners.configuration import CONFIG_NAMES
from runners.run_mvscan import build_run_id, valid_f1_seal


def load_plan() -> list[dict[str, object]]:
    seal_path = ROOT / "freeze" / "F1_SEALED.json"
    if not valid_f1_seal():
        raise RuntimeError("F2 refused: valid F1_SEALED artifact is absent or stale")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    plan_path = ROOT / seal.get("f2_run_plan", "")
    if not plan_path.is_file():
        raise RuntimeError("F2 refused: frozen F2 run plan is missing")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    runs = plan.get("runs")
    if not isinstance(runs, list) or not runs:
        raise RuntimeError("F2 refused: frozen F2 run plan is empty")
    if (
        plan.get("configurations") != list(CONFIG_NAMES)
        or plan.get("primary_seed") != 0
        or plan.get("reproducibility_seed") != 1
    ):
        raise RuntimeError("F2 refused: frozen plan header is invalid")
    expected_per_subject = {
        (configuration, 0, "ALWAYS") for configuration in CONFIG_NAMES
    }
    expected_per_subject.add(("B0", 1, "B0_SEED0_SUCCESS"))
    by_subject: dict[str, set[tuple[str, int, str]]] = {}
    identities = set()
    for record in runs:
        if not isinstance(record, dict):
            raise RuntimeError("F2 refused: plan row is not an object")
        relative = record.get("subject_manifest")
        if not isinstance(relative, str) or not relative.startswith(
            "benchmarks/subject_manifests/"
        ):
            raise RuntimeError("F2 refused: subject manifest path is invalid")
        subject_path = (ROOT / relative).resolve()
        if ROOT not in subject_path.parents or not subject_path.is_file():
            raise RuntimeError("F2 refused: subject manifest is missing")
        if sha256_file(subject_path) != record.get("subject_manifest_sha256"):
            raise RuntimeError("F2 refused: subject manifest hash mismatch")
        subject = json.loads(subject_path.read_text(encoding="utf-8"))
        if subject.get("accepted_build") is not True:
            raise RuntimeError("F2 refused: subject is not build-accepted")
        configuration = record.get("configuration")
        seed = record.get("seed")
        condition = record.get("condition")
        repetition = record.get("repetition")
        identity = (relative, configuration, seed, repetition)
        if (
            configuration not in CONFIG_NAMES
            or not isinstance(seed, int)
            or not isinstance(condition, str)
            or condition not in {"ALWAYS", "B0_SEED0_SUCCESS"}
            or repetition != 1
            or identity in identities
        ):
            raise RuntimeError("F2 refused: plan row identity is invalid")
        identities.add(identity)
        by_subject.setdefault(relative, set()).add(
            (configuration, seed, condition)
        )
    if any(shape != expected_per_subject for shape in by_subject.values()):
        raise RuntimeError("F2 refused: per-subject run matrix is incomplete")
    return runs


def completed_attempts() -> dict[str, list[dict[str, object]]]:
    """Index terminal attempts by frozen run identity for safe resumption."""
    result: dict[str, list[dict[str, object]]] = {}
    for path in sorted((ROOT / "runs").glob("*/run_manifest.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        run_id = document.get("run_id")
        status = document.get("terminal_status")
        if not isinstance(run_id, str) or not isinstance(status, str):
            raise RuntimeError("F2 resume refused: malformed terminal run manifest")
        result.setdefault(run_id, []).append(document)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.resume and not args.execute:
        parser.error("--resume requires --execute")
    runs = load_plan()
    if not args.execute:
        print(json.dumps({"guard": "PASS", "planned_runs": len(runs)}, sort_keys=True))
        return 0
    existing = completed_attempts()
    if existing and not args.resume:
        raise RuntimeError("F2 execution refused: terminal attempts exist; use --resume")
    successful_b0 = set()
    for record in runs:
        subject_manifest = str(record["subject_manifest"])
        subject = json.loads((ROOT / subject_manifest).read_text(encoding="utf-8"))
        run_id = build_run_id(
            subject["dataset"],
            subject["subject_id"],
            subject["revision_role"],
            str(record["configuration"]),
            int(record["seed"]),
            int(record.get("repetition", 1)),
        )
        terminal = existing.get(run_id, [])
        if len(terminal) > 1:
            raise RuntimeError("F2 resume refused: duplicate terminal attempts for " + run_id)
        if terminal:
            manifest = terminal[0]
            if (
                record["configuration"] == "B0"
                and int(record["seed"]) == 0
                and manifest.get("terminal_status") == "SUCCESS"
            ):
                successful_b0.add(subject_manifest)
            continue
        condition = record.get("condition", "ALWAYS")
        if condition == "B0_SEED0_SUCCESS" and subject_manifest not in successful_b0:
            continue
        if condition not in {"ALWAYS", "B0_SEED0_SUCCESS"}:
            raise RuntimeError("F2 refused: unknown frozen run condition")
        command = [
            sys.executable,
            "-m",
            "runners.run_mvscan",
            str(ROOT / subject_manifest),
            "--configuration",
            str(record["configuration"]),
            "--seed",
            str(record["seed"]),
            "--repetition",
            str(record.get("repetition", 1)),
            "--execute",
        ]
        completed = subprocess.run(
            command, cwd=ROOT, check=True, text=True, capture_output=True
        )
        run_path = Path(completed.stdout.strip().splitlines()[-1])
        manifest = json.loads((run_path / "run_manifest.json").read_text(encoding="utf-8"))
        existing.setdefault(run_id, []).append(manifest)
        if (
            record["configuration"] == "B0"
            and int(record["seed"]) == 0
            and manifest.get("terminal_status") == "SUCCESS"
        ):
            successful_b0.add(subject_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
