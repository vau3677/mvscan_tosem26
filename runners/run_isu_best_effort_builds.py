#!/usr/bin/env python3
"""Run all selected ISU native projects with bounded parallelism."""

from __future__ import annotations

import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import sys

from runners.common import ROOT

SELECTION = ROOT / "benchmarks" / "isu" / "best_effort_selected_projects.csv"
OUTPUT = ROOT / "benchmarks" / "isu" / "best_effort_build_batch_results.csv"


def run(row: dict[str, str]) -> dict[str, str]:
    command = [
        sys.executable, "-m", "runners.isu_best_effort_builds",
        "--source-id", row["source_id"], "--project-root", row["project_root"],
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    return {
        "source_id": row["source_id"], "project_root": row["project_root"],
        "exit_code": str(result.returncode), "stdout": result.stdout.strip(),
        "stderr_tail": result.stderr[-4000:].strip(),
    }


def main() -> int:
    with SELECTION.open(newline="", encoding="utf-8") as stream:
        selected = list(csv.DictReader(stream))
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run, row): row for row in selected}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps(result, sort_keys=True), flush=True)
    results.sort(key=lambda row: (row["source_id"], row["project_root"]))
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("source_id", "project_root", "exit_code", "stdout", "stderr_tail"), lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    print(json.dumps({
        "attempted_projects": len(results),
        "runner_failures": sum(row["exit_code"] != "0" for row in results),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
