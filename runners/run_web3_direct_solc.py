#!/usr/bin/env python3
"""Run complete-tree direct-solc attempts for source-only Web3Bugs snapshots."""

from __future__ import annotations

import concurrent.futures
import csv
import json

from runners.best_effort_builds import ROOT, build_snapshot

SELECTIONS = {
    "3": "0.8.17",
    "6": "0.7.6",
    "7": "0.6.12",
    "18": "0.8.17",
    "19": "0.8.4",
    "20": "0.8.3",
    "38": "0.8.7",
    "39": "0.8.4",
    "55": "0.8.7",
    "62": "0.8.10",
    "80": "0.8.6",
    "90": "0.8.17",
    "125": "0.6.12",
}
UNRESOLVED = {
    "14": "no single compiler satisfies exact pragmas 0.6.12 and 0.8.4 across the complete snapshot",
    "32": "no single compiler satisfies exact pragmas 0.7.5 and 0.8.6 across the complete snapshot; 0.7.5 is also absent from the frozen inventory",
}


def run(item: tuple[str, str]) -> dict[str, str]:
    snapshot_id, version = item
    helper = ROOT / "runners" / "direct_solc_build.py"
    command = f"/usr/bin/python3 {helper} --version {version}"
    try:
        manifest = build_snapshot(
            snapshot_id,
            command,
            f"complete-tree direct Standard JSON using frozen solc {version} selected from the intersection of all declared source pragmas",
            ".",
        )
        return {"snapshot_id": snapshot_id, "result": "ATTEMPT_RECORDED", "manifest": manifest.relative_to(ROOT).as_posix()}
    except Exception as exc:
        return {"snapshot_id": snapshot_id, "result": "ORCHESTRATION_ERROR", "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    unresolved_path = ROOT / "benchmarks" / "web3bugs" / "best_effort_direct_solc_unresolved.csv"
    with unresolved_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("snapshot_id", "status", "reason"), lineterminator="\n")
        writer.writeheader()
        for snapshot_id, reason in sorted(UNRESOLVED.items(), key=lambda item: int(item[0])):
            writer.writerow({"snapshot_id": snapshot_id, "status": "UNRESOLVED_NO_COMPATIBLE_FROZEN_COMPILER", "reason": reason})
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run, item) for item in SELECTIONS.items()]
        for future in concurrent.futures.as_completed(futures):
            print(json.dumps(future.result(), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
