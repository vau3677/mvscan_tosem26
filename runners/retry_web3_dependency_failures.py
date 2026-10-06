#!/usr/bin/env python3
"""Retry preserved Web3Bugs dependency failures after acquisition-only corrections."""

from __future__ import annotations

import concurrent.futures
import csv
import json
from pathlib import Path

from runners.best_effort_builds import ATTEMPTS, LEDGER, ROOT, build_snapshot


def main() -> int:
    ledger = {row["attempt_id"]: row for row in csv.DictReader(LEDGER.open(newline="", encoding="utf-8"))}
    selected = {}
    for path in ATTEMPTS.glob("*/*/attempt_manifest.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["terminal_status"] != "DEPENDENCY_FAILURE":
            continue
        record = ledger.get(manifest["attempt_id"])
        if not record:
            continue
        key = (manifest["snapshot_id"], manifest["project_root"], record["build_command"])
        selected[key] = manifest

    def execute(key: tuple[str, str, str]) -> dict[str, str]:
        snapshot_id, project_root, command = key
        try:
            path = build_snapshot(
                snapshot_id,
                command,
                "retry of preserved dependency failure after disabling unrelated lifecycle scripts and rewriting obsolete GitHub transports to HTTPS",
                project_root,
            )
            return {"snapshot_id": snapshot_id, "project_root": project_root, "manifest": path.relative_to(ROOT).as_posix()}
        except Exception as exc:
            return {"snapshot_id": snapshot_id, "project_root": project_root, "error": f"{type(exc).__name__}: {exc}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(execute, sorted(selected)):
            print(json.dumps(result, sort_keys=True), flush=True)
    print(json.dumps({"retried_project_commands": len(selected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
