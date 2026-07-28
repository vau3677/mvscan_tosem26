from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

BEFORE = (
    ROOT
    / "results"
    / "pre-exact-witness-repair"
    / "classification"
)

AFTER = ROOT / "results" / "classification"


def canonical_finding(finding):
    return {
        "pattern": finding.get("pattern"),
        "vars": finding.get("vars", []),
        "tx_set": finding.get("tx_set", []),
        "op_patterns": finding.get("op_patterns", []),
        "shape": finding.get("shape", {}),
        "writers": finding.get("writers", []),
        "readers": finding.get("readers", []),
    }


def load(path):
    return json.loads(path.read_text())


def main():
    before_files = {
        path.name: path
        for path in BEFORE.glob("*.json")
    }

    after_files = {
        path.name: path
        for path in AFTER.glob("*.json")
    }

    common = sorted(
        set(before_files)
        & set(after_files)
    )

    if not common:
        raise SystemExit(
            "No matching pre/post classification JSON files found"
        )

    for filename in common:
        before = load(before_files[filename])
        after = load(after_files[filename])

        print(f"\n=== {filename} ===")
        print("before findings:", len(before))
        print("after findings: ", len(after))

        before_core = {
            (
                item.get("pattern"),
                json.dumps(
                    item.get("vars", []),
                    sort_keys=True,
                ),
                tuple(item.get("tx_set", [])),
            )
            for item in before
        }

        after_core = {
            (
                item.get("pattern"),
                json.dumps(
                    item.get("vars", []),
                    sort_keys=True,
                ),
                tuple(item.get("tx_set", [])),
            )
            for item in after
        }

        lost = before_core - after_core
        gained = after_core - before_core

        print("core signatures lost:  ", len(lost))
        print("core signatures gained:", len(gained))

        if lost:
            print("LOST:")
            for item in sorted(
                lost,
                key=str,
            ):
                print(" ", item)

        if gained:
            print("GAINED:")
            for item in sorted(
                gained,
                key=str,
            ):
                print(" ", item)


if __name__ == "__main__":
    main()