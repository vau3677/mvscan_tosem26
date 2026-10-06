#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from runners.common import ROOT, sha256_file, write_json_new

SOURCES = (
    ("isu", "https://github.com/HumblePLSE/SolidityStateStudy.git", "985e0032449aaa4fec4b6d2f9f7902525cbbb736", "SolidityStateStudy"),
    ("web3bugs", "https://github.com/ZhangZhuoSJTU/Web3Bugs.git", "fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4", "Web3Bugs"),
)

def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.strip()

def acquire(dataset: str, repository: str, commit: str, name: str) -> dict[str, object]:
    final = ROOT / "benchmarks" / "sources" / name
    if final.exists():
        raise FileExistsError(f"refusing to overwrite {final}")
    attempt = ROOT / "benchmarks" / "acquisition_attempts" / dataset / "attempt-001"
    attempt.mkdir(parents=True, exist_ok=False)
    checkout = attempt / "repository"
    stdout_path, stderr_path = attempt / "stdout.txt", attempt / "stderr.txt"
    started_at = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    clean_env = {"HOME": os.environ["HOME"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/local/bin:/usr/bin:/bin", "TZ": "UTC", "GIT_TERMINAL_PROMPT": "0"}
    command = ["git", "clone", "--filter=blob:none", "--no-checkout", repository, str(checkout)]
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.run(command, env=clean_env, stdout=stdout, stderr=stderr, check=False)
        if process.returncode == 0:
            process = subprocess.run(["git", "-C", str(checkout), "checkout", "--detach", commit], env=clean_env, stdout=stdout, stderr=stderr, check=False)
    manifest: dict[str, object] = {
        "attempt_id": "attempt-001", "command": command, "commit_requested": commit,
        "dataset": dataset, "duration_seconds": time.monotonic() - start,
        "exit_code": process.returncode, "repository": repository, "started_at": started_at,
        "stderr_sha256": sha256_file(stderr_path), "stdout_sha256": sha256_file(stdout_path),
        "terminal_status": "SUCCESS" if process.returncode == 0 else "ACQUISITION_FAILURE",
    }
    if process.returncode != 0:
        write_json_new(attempt / "manifest.json", manifest)
        return manifest
    actual = git(checkout, "rev-parse", "HEAD")
    tree = git(checkout, "rev-parse", "HEAD^{tree}")
    status = git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
    if actual != commit or status:
        manifest.update({"actual_commit": actual, "git_tree": tree, "terminal_status": "ACCEPTANCE_FAILURE"})
        write_json_new(attempt / "manifest.json", manifest)
        return manifest
    final.parent.mkdir(parents=True, exist_ok=True)
    os.replace(checkout, final)
    manifest.update({"actual_commit": actual, "checkout_clean": True, "git_tree": tree, "relative_path": final.relative_to(ROOT).as_posix()})
    write_json_new(attempt / "manifest.json", manifest)
    return manifest

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acquire", action="store_true")
    args = parser.parse_args()
    if not args.acquire:
        raise SystemExit("use --acquire")
    records = [acquire(*spec) for spec in SOURCES]
    if not all(record["terminal_status"] == "SUCCESS" for record in records):
        print(json.dumps(records, sort_keys=True))
        return 1
    write_json_new(ROOT / "benchmarks/source_checkouts.json", {"checkouts": records, "schema_version": 1})
    print(json.dumps([{"dataset": record["dataset"], "commit": record["actual_commit"], "git_tree": record["git_tree"]} for record in records], sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
