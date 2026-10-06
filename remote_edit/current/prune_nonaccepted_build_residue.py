#!/usr/bin/env python3
"""Remove only unreferenced build workspaces and package-manager caches."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil

from runners.common import ROOT


REMOVABLE_NAMES = {"workspace", "yarn-cache", "npm-cache"}


def plan() -> tuple[set[str], list[dict[str, object]]]:
    accepted = {
        value
        for manifest in (ROOT / "benchmarks/subject_manifests").glob("*.json")
        if isinstance((value := json.loads(manifest.read_text(encoding="utf-8")).get("accepted_attempt_id")), str)
    }
    targets: list[dict[str, object]] = []
    for dataset in ("isu", "web3bugs"):
        build_root = ROOT / "benchmarks" / dataset / "best_effort_build_runs"
        if not build_root.is_dir():
            continue
        for attempt in sorted(build_root.glob("*/*")):
            if not attempt.is_dir() or attempt.name in accepted:
                continue
            for name in sorted(REMOVABLE_NAMES):
                child = attempt / name
                if child.is_dir():
                    targets.append({
                        "dataset": dataset,
                        "attempt_id": attempt.name,
                        "relative_path": child.relative_to(ROOT).as_posix(),
                        "component": name,
                    })
    return accepted, targets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    accepted, targets = plan()
    report: dict[str, object] = {
        "schema_version": 1,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "EXECUTE" if args.execute else "DRY_RUN",
        "accepted_attempt_count": len(accepted),
        "target_count": len(targets),
        "audit_estimated_reclaim_bytes": 49_900_000_000,
        "removable_names": sorted(REMOVABLE_NAMES),
        "targets": targets,
    }
    if args.execute:
        removed = []
        for row in targets:
            target = ROOT / str(row["relative_path"])
            if target.name not in REMOVABLE_NAMES or row["attempt_id"] in accepted:
                raise RuntimeError(f"safety invariant failed: {target}")
            shutil.rmtree(target)
            if target.exists():
                raise RuntimeError(f"failed to remove: {target}")
            removed.append(str(row["relative_path"]))
        report["removed_count"] = len(removed)
        report["status"] = "COMPLETE"
    report_path = ROOT / "reports" / (
        "NONACCEPTED_RESIDUE_PRUNE.json" if args.execute else "NONACCEPTED_RESIDUE_PRUNE.dry-run.json"
    )
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("mode", "accepted_attempt_count", "target_count", "audit_estimated_reclaim_bytes")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
