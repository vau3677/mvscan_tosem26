#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, json, os, shutil
from collections import Counter
from pathlib import Path

from runners.common import ROOT, canonical_bytes, sha256_file
from runners.run_mvscan import valid_f1_seal

SEAL=ROOT/"freeze/F2_SEALED.json"
UNION_SOURCE=ROOT/"reports/CROSS_ABLATION_UNION_INVENTORY.preseal.json"
UNION_FROZEN=ROOT/"freeze/CROSS_ABLATION_UNION_INVENTORY.json"
HANDOFF=ROOT/"freeze/human_handoff"

def record(path: Path) -> dict[str, object]:
    return {"path":path.relative_to(ROOT).as_posix(),"bytes":path.stat().st_size,"sha256":sha256_file(path)}

def main() -> int:
    if SEAL.exists(): raise RuntimeError("F2 seal already exists")
    if not valid_f1_seal(): raise RuntimeError("valid F1 seal required")
    hm=json.loads((HANDOFF/"MANIFEST.json").read_text())
    for item in hm.get("files",[]):
        p=HANDOFF/item["path"]
        if not p.is_file() or p.stat().st_size!=item["bytes"] or sha256_file(p)!=item["sha256"]:
            raise RuntimeError("handoff manifest mismatch: "+str(item["path"]))
    if UNION_FROZEN.exists():
        if sha256_file(UNION_FROZEN)!=sha256_file(UNION_SOURCE): raise RuntimeError("existing frozen union differs")
    else:
        temp=UNION_FROZEN.with_suffix(".json.tmp"); shutil.copyfile(UNION_SOURCE,temp); os.replace(temp,UNION_FROZEN)
    run_files=[]; statuses=Counter(); runs=0
    for manifest_path in sorted((ROOT/"runs").glob("*/run_manifest.json")):
        manifest=json.loads(manifest_path.read_text()); runs+=1; statuses[str(manifest.get("terminal_status"))]+=1
        files=[manifest_path]
        for name in ("detector.json.zst","detector.canonical.json.zst","stdout.log","stderr.log","process_metrics.json"):
            p=manifest_path.parent/name
            if p.is_file(): files.append(p)
        run_files.extend(record(p) for p in files)
        if manifest.get("terminal_status")=="SUCCESS":
            for key in ("raw_json_storage","canonical_json_storage"):
                storage=manifest.get(key,{})
                p=manifest_path.parent/str(storage.get("path",""))
                if not p.is_file() or p.stat().st_size!=storage.get("compressed_bytes") or sha256_file(p)!=storage.get("compressed_sha256"):
                    raise RuntimeError(f"stored detector artifact mismatch: {manifest_path.parent.name}:{key}")
    fixed=[]
    for rel in ("freeze/F1_SEALED.json","freeze/F2_run_plan.json","freeze/CROSS_ABLATION_UNION_INVENTORY.json","freeze/human_handoff/MANIFEST.json","protocol/MVSCAN_EVALUATION_PLAN.md","protocol/CROSS_ABLATION_UNION_AMENDMENT.md","protocol/F2_LOSSLESS_STORAGE_AMENDMENT.md","deviations/deviation_log.csv"):
        p=ROOT/rel
        if not p.is_file(): raise RuntimeError("missing F2 dependency: "+rel)
        fixed.append(record(p))
    seal={"schema_version":1,"status":"F2_SEALED","sealed_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
      "run_count":runs,"terminal_status_counts":dict(sorted(statuses.items())),"fixed_artifacts":fixed,
      "run_artifacts":run_files,"human_handoff":{"primary_web3bugs":hm["primary_web3bugs"],"agreement_web3bugs":hm["agreement_web3bugs"],"isu_known_findings":hm["isu_known_findings"]}}
    temp=SEAL.with_suffix(".json.tmp"); temp.write_bytes(canonical_bytes(seal)+b"\n"); os.replace(temp,SEAL)
    print(json.dumps({"status":"F2_SEALED","runs":runs,"run_artifacts":len(run_files),"terminal_status_counts":dict(statuses)},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
