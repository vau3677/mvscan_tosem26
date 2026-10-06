#!/usr/bin/env python3
"""Compare authoritative B0 seed 0 with the B0 seed 1 sensitivity runs."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from runners.common import ROOT, canonical_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifests = {}
    for path in (ROOT / "runs").glob("*/run_manifest.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("configuration") != "B0" or document.get("python_hash_seed") not in {0, 1}:
            continue
        manifests[(document["dataset"], str(document["subject"]), document["python_hash_seed"])] = document
    datasets = {}
    for dataset in sorted({key[0] for key in manifests}):
        subjects = sorted({key[1] for key in manifests if key[0] == dataset})
        comparisons, statuses, missing = [], Counter(), []
        for subject in subjects:
            seed0, seed1 = manifests.get((dataset, subject, 0)), manifests.get((dataset, subject, 1))
            if seed0 is None or seed1 is None:
                missing.append({"subject": subject, "missing_seed": 0 if seed0 is None else 1})
                continue
            statuses[(seed0.get("terminal_status"), seed1.get("terminal_status"))] += 1
            if seed0.get("terminal_status") == seed1.get("terminal_status") == "SUCCESS":
                same = seed0.get("canonical_json_sha256") == seed1.get("canonical_json_sha256")
                comparisons.append({"subject": subject, "exact_match": same,
                                    "seed0_sha256": seed0.get("canonical_json_sha256"),
                                    "seed1_sha256": seed1.get("canonical_json_sha256")})
        datasets[dataset] = {
            "seed0_is_authoritative": True,
            "paired_successes": len(comparisons),
            "exact_matches": sum(row["exact_match"] for row in comparisons),
            "mismatches": [row for row in comparisons if not row["exact_match"]],
            "terminal_status_pairs": {"|".join(key): value for key, value in sorted(statuses.items())},
            "missing_pairs": missing,
        }
    result = {"schema_version": 1, "comparison": "B0 canonical JSON, seed 0 versus seed 1", "datasets": datasets}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(canonical_bytes(result).decode("utf-8") + "\n")
    print(json.dumps(datasets, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
