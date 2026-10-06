#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, re
from pathlib import Path

from runners.common import ROOT

OUT_OF_SCOPE_COMPONENTS = {
    "test", "tests", "testing", "mock", "mocks", "fixture", "fixtures",
    "harness", "harnesses", "example", "examples", "deps", "dependencies",
    "vendor", "vendors", "lib", "libs",
}
OUT_OF_SCOPE_BASENAME = re.compile(r"(?:mock|harness|test)\.sol$", re.IGNORECASE)

FIELDS=("snapshot_id","source_path","source_sha256","scope","scope_evidence")

def classify(path: str) -> tuple[str,str]:
    normalized=path.removeprefix("./")
    parts=normalized.split("/"); lower=[x.lower() for x in parts]
    if normalized.startswith("node_modules/") or normalized.startswith("@"):
        return "OUT_OF_SCOPE","separately versioned package/dependency path"
    if any(x in OUT_OF_SCOPE_COMPONENTS for x in lower[:-1]) or OUT_OF_SCOPE_BASENAME.search(lower[-1]):
        return "OUT_OF_SCOPE","deterministic test/mock/fixture/harness/example/dependency path rule"
    return "IN_SCOPE","first-party production-looking Solidity source; unmatched first-party remains in scope"

def main() -> int:
    ap=argparse.ArgumentParser();ap.add_argument("output",type=Path);ap.add_argument("--input",type=Path,default=ROOT/"benchmarks/web3bugs/source_scope.csv");a=ap.parse_args()
    rows=list(csv.DictReader(a.input.open(newline="",encoding="utf-8")))
    out=[]
    for row in rows:
        scope,evidence=classify(row["source_path"]);out.append({**row,"scope":scope,"scope_evidence":evidence})
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open("x",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(out)
    from collections import Counter
    print(json.dumps({"rows":len(out),"scope_counts":dict(Counter(x["scope"] for x in out))},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
