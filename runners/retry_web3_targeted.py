#!/usr/bin/env python3
from __future__ import annotations
import concurrent.futures, csv, json
from runners.best_effort_builds import ROOT, build_snapshot

CASES = [
    ("13", ".", "npm"),
    ("37", ".", None),
    ("43", ".", "npm-force"),
    ("57", "ibbtc", "npm-force"),
    ("69", "nftx-protocol-v2", "npm"),
    ("74", "Timeswap/Timeswap-V1-Convenience", None),
    ("96", "Timeswap/Convenience", None),
    ("97", ".", None),
    ("102", ".", "npm-force"),
    ("113", ".", "yarn-unfrozen"),
]

with (ROOT / "benchmarks/web3bugs/best_effort_project_inventory.csv").open(newline="", encoding="utf-8") as stream:
    inventory = {(r["snapshot_id"], r["project_root"]): r for r in csv.DictReader(stream)}

def run(case):
    snapshot, root, manager = case
    row = inventory.get((snapshot, root))
    command = row["command"] if row else None
    evidence = row["command_evidence"] if row else None
    try:
        manifest = build_snapshot(
            snapshot, command,
            (evidence + f"; targeted dependency retry manager={manager or 'frozen-default'}") if evidence else None,
            root, manager,
        )
        return {"snapshot": snapshot, "root": root, "manager": manager, "manifest": manifest.relative_to(ROOT).as_posix()}
    except Exception as exc:
        return {"snapshot": snapshot, "root": root, "manager": manager, "error": f"{type(exc).__name__}: {exc}"}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    for result in executor.map(run, CASES):
        print(json.dumps(result, sort_keys=True), flush=True)
