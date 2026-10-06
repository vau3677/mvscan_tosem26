#!/usr/bin/env python3
import csv
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
rows = list(csv.DictReader((root / "human_review/web3bugs_agreement.csv").open()))
wanted = set()
for row in rows:
    packet = json.loads((root / "human_review" / row["packet"]).read_text())
    subject = str(packet["subject"])
    paths = {e["file"] for e in packet.get("source_excerpts", []) if e.get("file")}
    paths.update(w.get("reader", {}).get("file") for w in packet.get("reader_witnesses", []) if w.get("reader", {}).get("file"))
    relation = packet.get("relation", [])
    groups = [relation.get("members", []) if isinstance(relation, dict) else relation, packet.get("written_members", []), packet.get("potentially_stale_members", [])]
    for group in groups:
        for entity in group:
            key = entity.get("entity_key", []) if isinstance(entity, dict) else entity
            if isinstance(key, list) and len(key) > 1:
                paths.add(key[1])
    wanted.update((subject, path) for path in paths)

mapping = {}
for subject, path in sorted(wanted):
    base = root / "benchmarks/sources/Web3Bugs/contracts" / subject
    files = [item.relative_to(base).as_posix() for item in base.rglob("*") if item.is_file()]
    direct = path.lstrip("./")
    candidates = [direct] if direct in files else [item for item in files if item.endswith("/" + direct)]
    if not candidates:
        candidates = [item for item in files if pathlib.PurePosixPath(item).name == pathlib.PurePosixPath(direct).name]
    candidates.sort(key=lambda item: (len(item.split("/")), len(item), item))
    mapping[f"{subject}|{path}"] = {
        "path": candidates[0] if candidates else None,
        "ambiguous": len(candidates) > 1,
        "candidate_count": len(candidates),
    }

output.write_text(json.dumps(mapping, indent=2, sort_keys=True))
print(len(mapping), sum(v["path"] is not None for v in mapping.values()), sum(v["path"] is None for v in mapping.values()), sum(v["ambiguous"] for v in mapping.values()))
