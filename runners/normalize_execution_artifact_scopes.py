#!/usr/bin/env python3
"""Normalize accepted build hashes to the directory actually executed."""
from __future__ import annotations

import json
import os
from pathlib import Path

from runners.common import ROOT, build_artifact_state


def replace(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    changed = []
    for path in sorted((ROOT / "benchmarks/subject_manifests").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        source = ROOT / document["source_path"]
        current, files, byte_size = build_artifact_state(source)
        inputs = document.setdefault("expected_inputs", {})
        previous = inputs.get("build_sha256")
        if current is None or current == previous:
            continue
        accepted_workspace = inputs.get("accepted_workspace_build_sha256", previous)
        inputs["accepted_workspace_build_sha256"] = accepted_workspace
        inputs["build_sha256"] = current
        document["build_artifact_scope"] = "source_path"
        document["build_artifact_scope_correction"] = {
            "previous_workspace_sha256": accepted_workspace,
            "execution_scope_sha256": current,
            "execution_scope_file_count": files,
            "execution_scope_byte_size": byte_size,
            "reason": "accepted artifact hash covered the enclosing build workspace; runner executes source_path",
        }
        replace(path, document)
        changed.append({"manifest": path.name, "previous": previous, "current": current, "files": files, "bytes": byte_size})
    if len(changed) != 4:
        raise RuntimeError(f"expected exactly four artifact-scope corrections, found {len(changed)}")
    print(json.dumps({"corrected": changed, "count": len(changed)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
