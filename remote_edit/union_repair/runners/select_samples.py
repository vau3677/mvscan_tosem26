#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

PRIMARY_DOMAIN = "20260811"
AGREEMENT_DOMAIN = "20260811:agreement"

def digest(domain: str, global_candidate_id: str) -> str:
    return hashlib.sha256(domain.encode("utf-8") + global_candidate_id.encode("utf-8")).hexdigest()

def select_primary(candidate_ids: Iterable[str]) -> list[str]:
    ids = list(candidate_ids)
    if len(ids) != len(set(ids)):
        raise ValueError("global candidate IDs must be unique")
    if len(ids) <= 400:
        return sorted(ids)
    return [candidate_id for _, candidate_id in sorted((digest(PRIMARY_DOMAIN, candidate_id), candidate_id) for candidate_id in ids)[:400]]

def select_agreement(primary_ids: Iterable[str]) -> list[str]:
    ids = list(primary_ids)
    if len(ids) != len(set(ids)):
        raise ValueError("primary candidate IDs must be unique")
    return [candidate_id for _, candidate_id in sorted((digest(AGREEMENT_DOMAIN, candidate_id), candidate_id) for candidate_id in ids)[:200]]

def select_configurations(populations: Mapping[str, Iterable[str]]) -> dict[str, object]:
    by_configuration = {
        configuration: select_primary(candidate_ids)
        for configuration, candidate_ids in sorted(populations.items())
    }
    unique_primary = sorted({candidate_id for ids in by_configuration.values() for candidate_id in ids})
    return {
        "by_configuration": by_configuration,
        "unique_primary": unique_primary,
        "agreement": select_agreement(unique_primary),
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Apply the frozen selector only to already-frozen F2 IDs.")
    parser.add_argument("ids", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    document = json.loads(args.ids.read_text(encoding="utf-8"))
    if isinstance(document, dict):
        result = select_configurations(document)
    else:
        primary = select_primary(document)
        result = {"agreement": select_agreement(primary), "primary": primary}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
