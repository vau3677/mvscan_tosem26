#!/usr/bin/env python3
from __future__ import annotations
import concurrent.futures, json, subprocess, sys

CASES = [
    ("17ed21b4712c0b20cc36", ".", "node16-yarn1", "none", "Foundry build does not require inconsistent JavaScript lockfile"),
    ("190ff08406165ccf2990", ".", "node16-yarn1", "yarn", "Node 16 satisfies Hardhat's checked-in dependency engine range after Node 12 rejection"),
    ("3e4e01feaa76a5bfa74c", ".", "node16-npm8", "npm", "checked-in package-lock alternative after inconsistent checked-in Yarn lock"),
    ("55e1bbda13af0e5d9ef5", ".", "node18-npm10", "npm", "checked-in package-lock under dependency-required Node >=18"),
    ("597ae00db4b637e8d8ab", ".", "node18-yarn1", "corepack-yarn", "project-local Yarn Berry via Corepack"),
    ("66ca3e8adf0343f843ff", ".", "node18-yarn1", "corepack-yarn", "project-local Yarn Berry via Corepack"),
    ("7cb043d026c74611d6c4", ".", "node16-npm8", "npm-force", "checked-in npm lock with force limited to erroneous direct Darwin-only fsevents dependency"),
    ("9beb76425d2bf5942a4d", ".", "node18-yarn1", "yarn", "dependency engine explicitly requires Node >=18"),
    ("9d8daa19c1e936e9ba9e", ".", "node18-yarn1", "yarn", "dependency engine explicitly requires Node >=18"),
    ("a71bbe43cb08fee655f2", "contracts/bridge", "node16-yarn1", "yarn", "retry exact lock after transient/corrupt GitHub tar extraction"),
    ("ad517a7d673ed4aa19f4", "tge", "node16-npm8", "npm", "checked-in package-lock alternative after inconsistent checked-in Yarn lock"),
    ("afe6967172f4b9b0e34a", "governance", "node18-yarn1", "yarn", "dependency engine explicitly requires Node >=18"),
    ("afe6967172f4b9b0e34a", "registries", "node18-yarn1", "yarn", "dependency engine explicitly requires Node >=18"),
    ("afe6967172f4b9b0e34a", "tokenomics", "node16-npm8", "npm", "checked-in package-lock alternative after inconsistent checked-in Yarn lock"),
    ("d70057952f8081152c99", ".", "node18-yarn1", "corepack-yarn", "packageManager pins Yarn 4.0.0-rc.51 via Corepack"),
    ("e7689c5bacc48db39ccb", "paraspace-core", "node18-yarn1", "corepack-yarn", "project-local Yarn Berry via Corepack"),
]

def run(case):
    source, root, profile, manager, reason = case
    command = [sys.executable, "-m", "runners.isu_best_effort_builds", "--source-id", source,
               "--project-root", root, "--node-profile", profile, "--dependency-manager", manager]
    result = subprocess.run(command, text=True, capture_output=True)
    return {"source_id": source, "project_root": root, "reason": reason,
            "exit_code": result.returncode, "stdout": result.stdout.strip(), "stderr_tail": result.stderr[-3000:].strip()}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    for result in executor.map(run, CASES):
        print(json.dumps(result, sort_keys=True), flush=True)
