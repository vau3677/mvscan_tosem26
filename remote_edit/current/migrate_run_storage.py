#!/usr/bin/env python3
"""One-time, restartable migration of F2 JSON outputs to verified zstd storage."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import uuid

from runners.artifact_storage import compress_verified
from runners.common import ROOT


def replace_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp." + uuid.uuid4().hex)
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def migrate_run(manifest_path: Path) -> tuple[int, int]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run = manifest_path.parent
    changed = 0
    reclaimed = 0
    for label, filename, hash_field, storage_field in (
        ("raw", "detector.json", "raw_json_sha256", "raw_json_storage"),
        ("canonical", "detector.canonical.json", "canonical_json_sha256", "canonical_json_storage"),
    ):
        source = run / filename
        compressed = run / (filename + ".zst")
        if source.exists():
            before = source.stat().st_size
            record = compress_verified(source, expected_sha256=manifest.get(hash_field))
            manifest[storage_field] = record
            if label == "raw":
                manifest["detector_json"] = record["path"]
            changed += 1
            reclaimed += before - int(record["compressed_bytes"])
        elif compressed.exists():
            if storage_field not in manifest:
                raise RuntimeError(f"compressed artifact lacks storage manifest: {compressed}")
        elif manifest.get(hash_field) is not None:
            raise FileNotFoundError(f"manifested artifact is missing: {source}")
    if changed:
        manifest["storage_migrated_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        manifest["storage_schema_version"] = 1
        replace_json(manifest_path, manifest)
    return changed, reclaimed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    manifests = sorted((ROOT / "runs").glob("*/run_manifest.json"))
    if not args.execute:
        print(json.dumps({"mode": "DRY_RUN", "manifests": len(manifests)}, sort_keys=True))
        return 0
    artifacts = reclaimed = migrated_runs = 0
    for manifest_path in manifests:
        count, saved = migrate_run(manifest_path)
        artifacts += count
        reclaimed += saved
        migrated_runs += bool(count)
    print(json.dumps({
        "status": "COMPLETE",
        "manifests": len(manifests),
        "migrated_runs": migrated_runs,
        "compressed_artifacts": artifacts,
        "reclaimed_bytes": reclaimed,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
