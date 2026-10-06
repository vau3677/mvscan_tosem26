#!/usr/bin/env python3
"""Select repository-level ISU build roots while excluding vendored projects."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import PurePosixPath

from runners.common import ROOT

INPUT = ROOT / "benchmarks" / "isu" / "best_effort_project_inventory.csv"
OUTPUT = ROOT / "benchmarks" / "isu" / "best_effort_selected_projects.csv"
EXCLUDED_COMPONENTS = {"lib", "libs", "vendor", "vendors", "node_modules", "dependencies", "deps"}


def main() -> int:
    with INPUT.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
        fields = list(rows[0]) if rows else []
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["source_id"]].append(row)
    selected = []
    exclusions = []
    for source_id, candidates in sorted(grouped.items()):
        root = next((row for row in candidates if row["project_root"] == "."), None)
        if root:
            chosen = [root]
            for row in candidates:
                if row is not root:
                    exclusions.append({"source_id": source_id, "project_root": row["project_root"], "reason": "covered by repository-root native build"})
        else:
            eligible = []
            for row in candidates:
                parts = set(PurePosixPath(row["project_root"]).parts)
                if parts & EXCLUDED_COMPONENTS:
                    exclusions.append({"source_id": source_id, "project_root": row["project_root"], "reason": "vendored/dependency project root"})
                else:
                    eligible.append(row)
            eligible.sort(key=lambda row: (len(PurePosixPath(row["project_root"]).parts), row["project_root"]))
            chosen = []
            for row in eligible:
                path = PurePosixPath(row["project_root"])
                if any(PurePosixPath(parent["project_root"]) in path.parents for parent in chosen):
                    exclusions.append({"source_id": source_id, "project_root": row["project_root"], "reason": "covered by selected ancestor native build"})
                else:
                    chosen.append(row)
        for row in chosen:
            value = dict(row)
            value["selection_evidence"] = "repository root" if row["project_root"] == "." else "top-level non-vendored native project root"
            selected.append(value)
    output_fields = [*fields, "selection_evidence"]
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=output_fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(selected)
    exclusions_path = OUTPUT.with_name("best_effort_project_exclusions.csv")
    with exclusions_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("source_id", "project_root", "reason"), lineterminator="\n")
        writer.writeheader()
        writer.writerows(exclusions)
    print(json.dumps({
        "candidate_rows": len(rows),
        "selected_project_rows": len(selected),
        "selected_sources": len({row["source_id"] for row in selected}),
        "excluded_rows": len(exclusions),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
