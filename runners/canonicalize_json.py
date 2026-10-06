#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path
from runners.artifact_storage import read_json
from runners.common import canonical_bytes, sha256_bytes

def canonicalize(source: Path, destination: Path) -> str:
    value = read_json(source)
    payload = canonical_bytes(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(payload)
    return sha256_bytes(payload)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(canonicalize(args.source, args.destination))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
