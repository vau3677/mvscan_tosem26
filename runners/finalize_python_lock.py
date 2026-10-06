#!/usr/bin/env python3
"""Freeze an already-downloaded wheel closure without contacting a package index."""

from __future__ import annotations

import email.parser
import hashlib
import json
import os
from pathlib import Path
import zipfile

from runners.common import canonical_bytes, write_json_new

ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "environment" / "acquisition" / "python-wheels-001"
DOWNLOADS = ATTEMPT / "downloads"
WHEELHOUSE = ROOT / "environment" / "wheelhouse"
LOCK = ROOT / "environment" / "python.lock"
MANIFEST = ROOT / "environment" / "python_artifacts.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise RuntimeError(f"{path.name}: expected one METADATA, got {metadata_names}")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_names[0]))
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise RuntimeError(f"{path.name}: missing Name or Version")
    return name, version


def main() -> None:
    if WHEELHOUSE.exists() or LOCK.exists() or MANIFEST.exists():
        raise FileExistsError("refusing to overwrite an existing Python freeze")
    wheels = sorted(DOWNLOADS.glob("*.whl"), key=lambda item: item.name)
    if not wheels:
        raise RuntimeError("download attempt contains no wheels")
    records = []
    seen_names: set[str] = set()
    lock_rows = []
    for path in wheels:
        name, version = wheel_identity(path)
        normalized = name.lower().replace("_", "-")
        if normalized in seen_names:
            raise RuntimeError(f"duplicate distribution: {name}")
        seen_names.add(normalized)
        digest = sha256(path)
        records.append(
            {
                "filename": path.name,
                "name": name,
                "version": version,
                "sha256": digest,
                "byte_size": path.stat().st_size,
            }
        )
        lock_rows.append((normalized, f"{name}=={version} --hash=sha256:{digest}"))
    lock_bytes = (
        "# Generated before benchmark detector output; install with --require-hashes.\n"
        + "\n".join(row for _, row in sorted(lock_rows))
        + "\n"
    ).encode("utf-8")
    with LOCK.open("xb") as stream:
        stream.write(lock_bytes)
    write_json_new(
        MANIFEST,
        {
            "schema_version": 1,
            "python_version": "3.10.20",
            "platform": "linux/amd64",
            "resolver_host_python": "3.10",
            "requested": {
                "slither-analyzer": "0.11.3",
                "crytic-compile": "0.3.11",
            },
            "pip_options": ["--only-binary=:all:"],
            "artifacts": records,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        },
    )
    os.replace(DOWNLOADS, WHEELHOUSE)
    print(
        canonical_bytes(
            {
                "wheel_count": len(records),
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            }
        ).decode("utf-8"),
        end="",
    )


if __name__ == "__main__":
    main()
