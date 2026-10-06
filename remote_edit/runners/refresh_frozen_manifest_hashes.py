#!/usr/bin/env python3
"""Bind the canonical environment and every subject to the finalized runtime."""
from __future__ import annotations

import json
import os
from pathlib import Path

from runners.common import ROOT, sha256_file


def replace(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> int:
    daemonless_path = ROOT / "environment/daemonless_environment_manifest.json"
    compiler_path = ROOT / "environment/frozen_svm_compilers.json"
    environment_path = ROOT / "environment/environment_manifest.json"
    daemonless = json.loads(daemonless_path.read_text(encoding="utf-8"))
    if daemonless.get("status") != "COMPLETE":
        raise RuntimeError("daemonless environment is not complete")
    runtime_digest = daemonless["runtime_digest"]
    compiler_sha256 = sha256_file(compiler_path)

    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    environment["immutable_runtime_digest"] = runtime_digest
    environment["status"] = "COMPLETE"
    environment["unresolved"] = []
    replace(environment_path, environment)

    manifests = sorted((ROOT / "benchmarks/subject_manifests").glob("*.json"))
    if len(manifests) != 153:
        raise RuntimeError(f"expected 153 subject manifests, found {len(manifests)}")
    for path in manifests:
        document = json.loads(path.read_text(encoding="utf-8"))
        inputs = document.setdefault("expected_inputs", {})
        inputs["compiler_sha256"] = compiler_sha256
        inputs["environment_digest"] = runtime_digest
        replace(path, document)
    print(json.dumps({
        "compiler_sha256": compiler_sha256,
        "environment_digest": runtime_digest,
        "subject_manifests": len(manifests),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
