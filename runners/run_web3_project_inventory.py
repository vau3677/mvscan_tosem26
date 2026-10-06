#!/usr/bin/env python3
"""Run evidence-derived Web3Bugs native project builds with bounded concurrency."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import traceback

from runners.best_effort_builds import ROOT, build_snapshot

INVENTORY = ROOT / "benchmarks" / "web3bugs" / "best_effort_project_inventory.csv"


def execute(row: dict[str, str]) -> dict[str, str]:
    try:
        manifest = build_snapshot(
            row["snapshot_id"],
            row["command"],
            row["command_evidence"],
            row["project_root"],
        )
        return {
            "snapshot_id": row["snapshot_id"],
            "project_root": row["project_root"],
            "result": "ATTEMPT_RECORDED",
            "manifest": manifest.relative_to(ROOT).as_posix(),
        }
    except Exception as exc:  # preserve orchestration error without stopping other builds
        return {
            "snapshot_id": row["snapshot_id"],
            "project_root": row["project_root"],
            "result": "ORCHESTRATION_ERROR",
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--unresolved-only", action="store_true")
    args = parser.parse_args()
    rows = list(csv.DictReader(INVENTORY.open(newline="", encoding="utf-8")))
    if args.unresolved_only:
        rows = [row for row in rows if not row["selection_status"].startswith("RESOLVED")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = [executor.submit(execute, row) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            print(json.dumps(future.result(), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
