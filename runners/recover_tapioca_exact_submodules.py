#!/usr/bin/env python3
from __future__ import annotations
import csv, json, subprocess
from pathlib import Path
from runners.common import ROOT

source_id = "51822de69e2919a4a935"
root = ROOT / "benchmarks/isu/sources" / source_id
expected = {
    "gitsub_tapioca-sdk": ("90d1e8a16ebe278e86720bc9b69596f74320e749", "https://github.com/bapbao/tapioca-sdk-audit.git"),
    "tapioca-periph": ("a3b45512580f8a76be45c19f635689f48c0128c3", "https://github.com/vickey2968/tapioca-periph-audit.git"),
}
command = ["git"]
for name, (_, mirror) in expected.items():
    command.extend(["-c", f"submodule.{name}.url={mirror}"])
command.extend(["submodule", "update", "--init", "--recursive", "--depth", "1", *expected])
result = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=900)
log = ROOT / "benchmarks/isu/source_acquisition_logs" / source_id / "exact_submodule_mirror_recovery.log"
log.write_text(json.dumps({"command": command, "exit_code": result.returncode}, sort_keys=True) + "\n" + result.stdout + result.stderr, encoding="utf-8")
if result.returncode:
    raise SystemExit(result.returncode)
verified = {}
for path, (revision, mirror) in expected.items():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root / path, text=True).strip()
    if head != revision:
        raise RuntimeError(f"{path} HEAD {head} != exact gitlink {revision}")
    verified[path] = {"revision": head, "mirror": mirror}
manifest = log.with_name("exact_submodule_mirror_manifest.json")
manifest.write_text(json.dumps({"source_id": source_id, "verified_exact_submodules": verified}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
csv_path = ROOT / "benchmarks/isu/source_acquisition_best_effort.csv"
with csv_path.open(newline="", encoding="utf-8") as stream:
    reader = csv.DictReader(stream); fields = list(reader.fieldnames or []); rows = list(reader)
for row in rows:
    if row["source_id"] == source_id:
        row["submodule_status"] = "SUCCESS_EXACT_MIRRORS"
        row["acquisition_method"] = (row.get("acquisition_method", "") + "; exact gitlink objects fetched from public submodule mirrors").lstrip("; ")
with csv_path.open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n"); writer.writeheader(); writer.writerows(rows)
print(json.dumps({"source_id": source_id, "verified": verified}, sort_keys=True))
