#!/usr/bin/env python3
"""Refresh the canonical configuration manifest from frozen env files."""
from __future__ import annotations

import json
import os

from runners.common import ROOT, sha256_file
from runners.configuration import CONFIG_NAMES, detector_effective_config, load_named


def main() -> int:
    rows = []
    for name in CONFIG_NAMES:
        path = ROOT / "configs" / f"{name}.env"
        environment = load_named(name)
        rows.append({
            "configuration": name,
            "env_file": path.relative_to(ROOT).as_posix(),
            "env_sha256": sha256_file(path),
            "expected_detector_effective_config": detector_effective_config(environment),
            "runner_environment": environment,
        })
    destination = ROOT / "configs/configurations.json"
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps({
        "paper_configurations": rows,
        "primary_seed": 0,
        "reproducibility_seed": 1,
        "schema_version": 1,
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    print(json.dumps({"configurations": len(rows), "status": "COMPLETE"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
