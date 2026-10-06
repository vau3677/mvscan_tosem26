#!/usr/bin/env python3
"""Verify and extract the frozen official Foundry release without overwriting."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile

from runners.common import write_json_new

ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "environment" / "acquisition" / "foundry-v1.5.1-001"
ARCHIVE = ATTEMPT / "foundry_v1.5.1_linux_amd64.tar.gz"
ATTESTATION = ATTEMPT / "foundry_v1.5.1_linux_amd64.attestation.txt"
RELEASE = ATTEMPT / "release.json"
DESTINATION = ROOT / "environment" / "toolchains" / "foundry-v1.5.1"
MANIFEST = ROOT / "environment" / "foundry_manifest.json"
EXPECTED_ARCHIVE = "73640b01bd9ed29fdb4965085099371f8cf0dbbec3e2086cf54564efc4dcfe88"
EXPECTED_ATTESTATION = "005673ce97f562f652cd1b6d7563958b33e996eeceaf7bbed133b419650027ad"
EXPECTED_MEMBERS = {"forge", "cast", "anvil", "chisel"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    if DESTINATION.exists() and not MANIFEST.exists():
        release = json.loads(RELEASE.read_text(encoding="utf-8"))
        if release.get("tag_name") != "v1.5.1":
            raise RuntimeError("release metadata tag mismatch")
        if sha256(ARCHIVE) != EXPECTED_ARCHIVE or sha256(ATTESTATION) != EXPECTED_ATTESTATION:
            raise RuntimeError("official release artifact hash mismatch")
        if {path.name for path in DESTINATION.iterdir()} != EXPECTED_MEMBERS:
            raise RuntimeError("existing Foundry destination has unexpected members")
        with tarfile.open(ARCHIVE, "r:gz") as archive:
            for member in archive.getmembers():
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(f"cannot read {member.name}")
                if hashlib.sha256(source.read()).hexdigest() != sha256(DESTINATION / member.name):
                    raise RuntimeError(f"existing binary differs from archive: {member.name}")
        records = [
            {
                "name": path.name,
                "relative_path": path.relative_to(ROOT).as_posix(),
                "byte_size": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in sorted(DESTINATION.iterdir())
        ]
        write_json_new(
            MANIFEST,
            {
                "schema_version": 1,
                "name": "Foundry",
                "version": "v1.5.1",
                "platform": "linux/amd64",
                "release_url": "https://github.com/foundry-rs/foundry/releases/tag/v1.5.1",
                "archive_sha256": EXPECTED_ARCHIVE,
                "attestation_sha256": EXPECTED_ATTESTATION,
                "binaries": records,
            },
        )
        print(json.dumps({"version": "v1.5.1", "binaries": len(records)}, sort_keys=True))
        return
    if DESTINATION.exists() or MANIFEST.exists():
        raise FileExistsError("refusing to overwrite an existing Foundry freeze")
    release = json.loads(RELEASE.read_text(encoding="utf-8"))
    if release.get("tag_name") != "v1.5.1":
        raise RuntimeError("release metadata tag mismatch")
    if sha256(ARCHIVE) != EXPECTED_ARCHIVE or sha256(ATTESTATION) != EXPECTED_ATTESTATION:
        raise RuntimeError("official release artifact hash mismatch")
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        if names != EXPECTED_MEMBERS:
            raise RuntimeError(f"unexpected archive members: {sorted(names)}")
        if any(not member.isfile() or "/" in member.name for member in members):
            raise RuntimeError("unsafe Foundry archive structure")
        temporary_parent = DESTINATION.parent
        temporary_parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".foundry-", dir=temporary_parent))
        try:
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(f"cannot read {member.name}")
                target = temporary / member.name
                with target.open("xb") as output:
                    output.write(source.read())
                target.chmod(0o755)
            records = [
                {
                    "name": path.name,
                    "relative_path": (DESTINATION / path.name).relative_to(ROOT).as_posix(),
                    "byte_size": path.stat().st_size,
                    "sha256": sha256(path),
                }
                for path in sorted(temporary.iterdir())
            ]
            os.replace(temporary, DESTINATION)
        except BaseException:
            if temporary.exists():
                for path in temporary.iterdir():
                    path.unlink()
                temporary.rmdir()
            raise
    write_json_new(
        MANIFEST,
        {
            "schema_version": 1,
            "name": "Foundry",
            "version": "v1.5.1",
            "platform": "linux/amd64",
            "release_url": "https://github.com/foundry-rs/foundry/releases/tag/v1.5.1",
            "archive_sha256": EXPECTED_ARCHIVE,
            "attestation_sha256": EXPECTED_ATTESTATION,
            "binaries": records,
        },
    )
    print(json.dumps({"version": "v1.5.1", "binaries": len(records)}, sort_keys=True))


if __name__ == "__main__":
    main()
