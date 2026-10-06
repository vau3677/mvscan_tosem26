#!/usr/bin/env python3
"""Lossless, hash-verified storage for large JSON evaluation artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import uuid
from typing import Any


ZSTD_LEVEL = 1


def _sha256_stream(command: list[str] | None, path: Path) -> str:
    digest = hashlib.sha256()
    if command is None:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    process = subprocess.Popen(command, stdout=subprocess.PIPE)
    assert process.stdout is not None
    with process.stdout:
        for block in iter(lambda: process.stdout.read(1024 * 1024), b""):
            digest.update(block)
    return_code = process.wait()
    if return_code != 0:
        raise OSError(f"decompression failed with exit code {return_code}: {path}")
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    if path.suffix != ".zst":
        return json.loads(path.read_text(encoding="utf-8"))
    process = subprocess.Popen(
        ["zstd", "-q", "-dc", "--", str(path)],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    with io.TextIOWrapper(process.stdout, encoding="utf-8") as stream:
        value = json.load(stream)
    return_code = process.wait()
    if return_code != 0:
        raise OSError(f"decompression failed with exit code {return_code}: {path}")
    return value


def compress_verified(source: Path, *, expected_sha256: str | None = None) -> dict[str, object]:
    """Compress source atomically; delete it only after exact stream verification."""
    if source.suffix == ".zst":
        raise ValueError("source is already compressed")
    destination = source.with_name(source.name + ".zst")
    if destination.exists():
        raise FileExistsError(destination)
    original_mode = source.stat().st_mode & 0o777
    if original_mode == 0:
        source.chmod(0o400)
    try:
        uncompressed_bytes = source.stat().st_size
        actual_sha256 = _sha256_stream(None, source)
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise ValueError(f"uncompressed SHA-256 mismatch: {source}")
        temporary = destination.with_name(destination.name + ".tmp." + uuid.uuid4().hex)
        try:
            subprocess.run(
                ["zstd", "-q", f"-{ZSTD_LEVEL}", "-T1", "-o", str(temporary), "--", str(source)],
                check=True,
            )
            subprocess.run(["zstd", "-q", "-t", "--", str(temporary)], check=True)
            roundtrip_sha256 = _sha256_stream(
                ["zstd", "-q", "-dc", "--", str(temporary)], temporary
            )
            if roundtrip_sha256 != actual_sha256:
                raise ValueError(f"decompressed SHA-256 mismatch: {source}")
            compressed_sha256 = _sha256_stream(None, temporary)
            compressed_bytes = temporary.stat().st_size
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        source.unlink()
        if original_mode == 0:
            destination.chmod(0)
        return {
            "path": destination.name,
            "compression": "zstd",
            "compression_level": ZSTD_LEVEL,
            "uncompressed_sha256": actual_sha256,
            "uncompressed_bytes": uncompressed_bytes,
            "compressed_sha256": compressed_sha256,
            "compressed_bytes": compressed_bytes,
            "roundtrip_verified": True,
        }
    finally:
        if source.exists() and original_mode == 0:
            source.chmod(0)
