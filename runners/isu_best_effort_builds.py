#!/usr/bin/env python3
"""Immutable best-effort build executor for exact acquired ISU sources."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import uuid

from runners.archive_web3_build_dependencies import archive_attempt
from runners.best_effort_builds import (
    NODE_VERSIONS, artifact_state, clean_environment, dependency_command,
    executable_command, file_state, original_mutations, run_command, write_manifest,
)
from runners.common import ROOT

ACQUISITION = ROOT / "benchmarks" / "isu" / "source_acquisition_best_effort.csv"
SELECTION = ROOT / "benchmarks" / "isu" / "best_effort_selected_projects.csv"
ATTEMPTS = ROOT / "benchmarks" / "isu" / "best_effort_build_runs"
LEDGER = ROOT / "benchmarks" / "isu" / "best_effort_build_attempts.csv"
LEDGER_FIELDS = (
    "attempt_id", "source_id", "repository", "requested_revision", "checkout_revision",
    "project_root", "started_at", "duration_seconds", "dependency_command",
    "dependency_exit_code", "build_command", "build_exit_code", "terminal_status",
    "node_profile", "node_version", "source_files_checked", "source_mutations",
    "artifact_files", "artifact_sha256", "manifest_path",
)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def append_ledger(record: dict[str, object]) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a+", encoding="utf-8", newline="") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0, os.SEEK_END)
        empty = stream.tell() == 0
        writer = csv.DictWriter(stream, fieldnames=LEDGER_FIELDS, lineterminator="\n")
        if empty:
            writer.writeheader()
        writer.writerow({field: record.get(field, "") for field in LEDGER_FIELDS})
        stream.flush()
        os.fsync(stream.fileno())
        fcntl.flock(stream, fcntl.LOCK_UN)


def hydrate_missing_submodules(
    source: Path,
    workspace: Path,
    attempt: Path,
    mirror_overrides: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Hydrate every top-level gitlink exactly before the mutation baseline."""
    config = subprocess.run(
        ["git", "-C", str(source), "config", "-f", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    names = {}
    for entry in config.stdout.splitlines():
        key, value = entry.split(maxsplit=1)
        names[value] = key[len("submodule."):-len(".path")]
    tree = subprocess.run(
        ["git", "-C", str(source), "ls-tree", "-r", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    gitlinks = []
    for line in tree.stdout.splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, commit = metadata.split()
        if mode == "160000" and kind == "commit":
            gitlinks.append((relative, commit))
    hydrated = []
    for relative, commit in gitlinks:
        if relative not in names:
            raise RuntimeError(f"cannot resolve exact submodule path: {relative}")
        name = names[relative]
        url_result = subprocess.run(
            ["git", "-C", str(source), "config", "-f", ".gitmodules", "--get", f"submodule.{name}.url"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
        )
        canonical_url = url_result.stdout.strip()
        url = (mirror_overrides or {}).get(relative, canonical_url)
        target = (workspace / relative).resolve()
        if workspace.resolve() not in target.parents:
            raise RuntimeError(f"submodule path escapes workspace: {relative}")
        if target.exists():
            shutil.rmtree(target)
        clone = subprocess.run(
            ["git", "clone", "--no-checkout", url, str(target)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if clone.returncode:
            raise RuntimeError(f"submodule clone failed for {relative}: {clone.stderr.strip()}")
        fetch = subprocess.run(
            ["git", "-C", str(target), "fetch", "--depth", "1", "origin", commit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if fetch.returncode:
            raise RuntimeError(f"submodule exact fetch failed for {relative}@{commit}: {fetch.stderr.strip()}")
        subprocess.run(["git", "-C", str(target), "checkout", "--detach", commit], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        actual = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        if actual != commit:
            raise RuntimeError(f"submodule revision mismatch for {relative}: {actual} != {commit}")
        nested = subprocess.run(
            ["git", "-C", str(target), "submodule", "update", "--init", "--recursive"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if nested.returncode:
            raise RuntimeError(f"nested submodule hydration failed for {relative}@{commit}: {nested.stderr.strip()}")
        shutil.rmtree(target / ".git")
        hydrated.append({
            "path": relative,
            "canonical_url": canonical_url,
            "acquisition_url": url,
            "mirror_override": str(url != canonical_url).lower(),
            "commit": commit,
        })
    write_manifest(attempt / "isolated_submodule_hydration.json", {"schema_version": 1, "submodules": hydrated})
    return hydrated


def hydrate_swh_contents(
    workspace: Path,
    attempt: Path,
    contents: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Hydrate exact archived import dependencies before the mutation baseline."""
    hydrated = []
    for relative, sha1_git in sorted((contents or {}).items()):
        target = (workspace / relative).resolve()
        if workspace.resolve() not in target.parents or target.exists():
            raise RuntimeError(f"invalid Software Heritage hydration target: {relative}")
        url = f"https://archive.softwareheritage.org/api/1/content/sha1_git:{sha1_git}/raw/"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        actual = hashlib.sha1(
            f"blob {len(data)}\0".encode("ascii") + data
        ).hexdigest()
        if actual != sha1_git:
            raise RuntimeError(
                f"Software Heritage Git blob mismatch for {relative}: {actual} != {sha1_git}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        hydrated.append({
            "path": relative,
            "sha1_git": sha1_git,
            "url": url,
            "byte_size": str(len(data)),
        })
    write_manifest(
        attempt / "isolated_swh_content_hydration.json",
        {"schema_version": 1, "contents": hydrated},
    )
    return hydrated


def seed_hardhat_compiler(attempt: Path, environment: dict[str, str], version: str) -> dict[str, str]:
    """Seed an isolated Hardhat native compiler cache from the archived toolchain."""
    source = ROOT / "environment" / "toolchains" / "solc" / version / "solc"
    if not source.is_file():
        raise ValueError(f"archived solc toolchain is unavailable: {version}")
    output = subprocess.check_output([str(source), "--version"], text=True)
    long_version = next(
        (line.split("Version:", 1)[1].strip() for line in output.splitlines() if "Version:" in line),
        version,
    )
    platform = "linux-amd64"
    filename = f"solc-linux-amd64-v{long_version}"
    cache = Path(environment["XDG_CACHE_HOME"]) / "hardhat-nodejs" / "compilers" / platform
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / filename
    shutil.copy2(source, target)
    target.chmod(0o755)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    cast = ROOT / "environment" / "toolchains" / "foundry-v1.5.1" / "cast"
    with target.open("rb") as compiler_stream:
        keccak256 = subprocess.check_output(
            [str(cast), "keccak"], stdin=compiler_stream, text=True
        ).strip()
    compiler_list = {
        "builds": [{
            "path": filename,
            "version": version,
            "build": long_version.split("+", 1)[1] if "+" in long_version else "",
            "longVersion": long_version,
            "keccak256": keccak256,
            "urls": [],
            "platform": platform,
        }],
        "releases": {version: filename},
        "latestRelease": version,
    }
    list_path = cache / "list.json"
    if list_path.is_file():
        existing = json.loads(list_path.read_text(encoding="utf-8"))
        existing["builds"].extend(compiler_list["builds"])
        existing["releases"].update(compiler_list["releases"])
        compiler_list = existing
        list_path.unlink()
    write_manifest(list_path, compiler_list)
    record = {
        "version": version,
        "long_version": long_version,
        "platform": platform,
        "source": source.relative_to(ROOT).as_posix(),
        "cache_path": target.relative_to(attempt).as_posix(),
        "sha256": digest,
        "keccak256": keccak256,
    }
    write_manifest(attempt / f"hardhat_compiler_seed_{version}.json", record)
    return record


def build(
    source_id: str,
    project_root_value: str,
    command_override: str | None = None,
    command_evidence_override: str | None = None,
    node_profile_override: str | None = None,
    dependency_manager_override: str | None = None,
    dependency_command_override: str | None = None,
    environment_overrides: dict[str, str] | None = None,
    hydrate_submodules: bool = False,
    submodule_mirrors: dict[str, str] | None = None,
    swh_contents: dict[str, str] | None = None,
    hardhat_solc_versions: list[str] | None = None,
) -> Path:
    acquired = next(
        row for row in rows(ACQUISITION)
        if row["source_id"] == source_id and row["status"].startswith("ACQUIRED")
    )
    selected = next((
        row for row in rows(SELECTION)
        if row["source_id"] == source_id and row["project_root"] == project_root_value
    ), None)
    if command_override and not command_evidence_override:
        raise ValueError("command override requires command evidence")
    if selected is None and not command_override:
        raise ValueError("source/project root is not in the selected inventory")
    source = ROOT / acquired["source_path"]
    started = dt.datetime.now(dt.timezone.utc)
    attempt_id = f"isu-{source_id}-{started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex}"
    attempt = ATTEMPTS / source_id / attempt_id
    attempt.mkdir(parents=True, exist_ok=False)
    workspace = attempt / "workspace"
    shutil.copytree(source, workspace, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    hydrated_submodules = hydrate_missing_submodules(
        source, workspace, attempt, submodule_mirrors
    ) if hydrate_submodules else []
    hydrated_swh_contents = hydrate_swh_contents(workspace, attempt, swh_contents)
    baseline = file_state(workspace)
    baseline_path = attempt / "original_files.json"
    write_manifest(baseline_path, baseline)
    project_root = (workspace / project_root_value).resolve()
    if workspace.resolve() not in (project_root, *project_root.parents) or not project_root.is_dir():
        raise ValueError("selected project root is invalid")
    profile = node_profile_override or (selected["node_profile"] if selected else "node16-npm8")
    node_version = NODE_VERSIONS[profile]
    environment = clean_environment(attempt, node_version)
    if environment_overrides:
        environment.update(environment_overrides)
    hardhat_compiler_seed = [
        seed_hardhat_compiler(attempt, environment, version)
        for version in (hardhat_solc_versions or [])
    ]
    build_command = command_override or selected["command"]
    install_command = dependency_command(project_root, build_command, node_version)
    if dependency_command_override:
        install_command = executable_command(dependency_command_override, node_version)
    elif dependency_manager_override == "none":
        install_command = None
    elif dependency_manager_override == "npm":
        npm = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "npm"
        install_command = [str(npm), "ci" if (project_root / "package-lock.json").is_file() else "install", "--no-audit", "--no-fund", "--ignore-scripts"]
        if node_version == "16.20.2":
            install_command.append("--legacy-peer-deps")
    elif dependency_manager_override == "yarn":
        node = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "node"
        yarn = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin" / "yarn.js"
        install_command = [str(node), str(yarn), "install", "--non-interactive", "--ignore-scripts"]
        if (project_root / "yarn.lock").is_file():
            install_command.append("--frozen-lockfile")
    elif dependency_manager_override == "corepack-yarn":
        corepack = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "corepack"
        install_command = [str(corepack), "yarn", "install", "--immutable", "--mode=skip-build"]
    elif dependency_manager_override == "corepack-yarn3":
        corepack = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "corepack"
        install_command = [str(corepack), "yarn@3.2.1", "install", "--immutable", "--mode=skip-build"]
    elif dependency_manager_override == "corepack-yarn331":
        corepack = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "corepack"
        install_command = [str(corepack), "yarn@3.3.1", "install", "--immutable", "--mode=skip-build"]
    elif dependency_manager_override in {"yarn2-immutable", "yarn3-immutable"}:
        node = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "node"
        releases = sorted((project_root / ".yarn" / "releases").glob("*.cjs"))
        if len(releases) != 1:
            raise ValueError(f"expected one checked-in Yarn release, found {len(releases)}")
        install_command = [str(node), str(releases[0]), "install", "--immutable"]
        if dependency_manager_override == "yarn2-immutable":
            install_command.append("--skip-builds")
        else:
            install_command.append("--mode=skip-build")
    elif dependency_manager_override == "npm-force":
        npm = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "npm"
        install_command = [str(npm), "ci" if (project_root / "package-lock.json").is_file() else "install", "--no-audit", "--no-fund", "--ignore-scripts", "--force"]
    elif dependency_manager_override == "npm-unlocked":
        npm = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "npm"
        install_command = [str(npm), "install", "--package-lock=false", "--no-audit", "--no-fund", "--ignore-scripts"]
    elif dependency_manager_override == "yarn-unfrozen":
        node = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "node"
        yarn = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin" / "yarn.js"
        install_command = [str(node), str(yarn), "install", "--non-interactive", "--ignore-scripts", "--pure-lockfile"]
    install = None
    if install_command:
        install = run_command(
            install_command, project_root, environment,
            attempt / "dependency.stdout.log", attempt / "dependency.stderr.log",
        )
    can_build = install is None or (install["exit_code"] == 0 and not install["timed_out"])
    build_result = None
    if can_build:
        build_result = run_command(
            executable_command(build_command, node_version), project_root, environment,
            attempt / "build.stdout.log", attempt / "build.stderr.log",
        )
    mutations = original_mutations(workspace, baseline)
    artifact_digest, artifact_files, artifact_bytes = artifact_state(workspace)
    if install is not None and install["timed_out"]:
        terminal = "DEPENDENCY_TIMEOUT"
    elif install is not None and install["exit_code"] != 0:
        terminal = "DEPENDENCY_FAILURE"
    elif build_result is None:
        terminal = "BUILD_NOT_STARTED"
    elif build_result["timed_out"]:
        terminal = "BUILD_TIMEOUT"
    elif build_result["exit_code"] != 0:
        terminal = "BUILD_FAILURE"
    elif mutations:
        terminal = "PROHIBITED_EDIT"
    elif not artifact_digest:
        terminal = "SUCCESS_NO_ARTIFACTS"
    else:
        terminal = "SUCCESS"
    finished = dt.datetime.now(dt.timezone.utc)
    manifest = {
        "schema_version": 1,
        "attempt_id": attempt_id,
        "dataset": "isu",
        "source_id": source_id,
        "repository": acquired["repository"],
        "requested_revision": acquired["requested_revision"],
        "checkout_revision": acquired["checkout_revision"],
        "git_tree": acquired["git_tree"],
        "source_path": acquired["source_path"],
        "workspace": workspace.relative_to(ROOT).as_posix(),
        "project_root": project_root_value,
        "build_command_evidence": command_evidence_override or selected["command_evidence"],
        "project_selection_evidence": selected["selection_evidence"] if selected else "complete source-only repository root",
        "node_profile": profile,
        "node_version": node_version,
        "node_selection_evidence": (
            f"best-effort explicit retry override: {node_profile_override}"
            if node_profile_override else
            (selected["node_selection_evidence"] if selected else "not applicable to direct compiler build; runner fallback environment")
        ),
        "best_effort_deviation": {
            "exact_memory_limit_enforced": False,
            "swap_disabled": False,
            "network_enabled_for_dependency_acquisition_and_compiler_downloads": True,
            "cpu_affinity_count": 4,
            "authorization": "user explicitly authorized ISU repository acquisition and best-effort builds",
        },
        "dependency": install,
        "dependency_manager_override": dependency_manager_override,
        "dependency_command_override": dependency_command_override,
        "environment_overrides": environment_overrides or {},
        "hardhat_compiler_seed": hardhat_compiler_seed,
        "isolated_submodule_hydration": hydrated_submodules,
        "isolated_swh_content_hydration": hydrated_swh_contents,
        "build": build_result,
        "original_files_manifest": baseline_path.relative_to(ROOT).as_posix(),
        "original_file_count": len(baseline),
        "original_file_mutations": mutations,
        "artifact_sha256": artifact_digest,
        "artifact_file_count": artifact_files,
        "artifact_byte_size": artifact_bytes,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": (finished - started).total_seconds(),
        "terminal_status": terminal,
    }
    manifest_path = attempt / "attempt_manifest.json"
    write_manifest(manifest_path, manifest)
    append_ledger({
        "attempt_id": attempt_id, "source_id": source_id,
        "repository": acquired["repository"], "requested_revision": acquired["requested_revision"],
        "checkout_revision": acquired["checkout_revision"], "project_root": project_root_value,
        "started_at": manifest["started_at"], "duration_seconds": manifest["duration_seconds"],
        "dependency_command": json.dumps(install["command"]) if install else "",
        "dependency_exit_code": install["exit_code"] if install else "",
        "build_command": build_command, "build_exit_code": build_result["exit_code"] if build_result else "",
        "terminal_status": terminal, "node_profile": profile, "node_version": node_version,
        "source_files_checked": len(baseline), "source_mutations": len(mutations),
        "artifact_files": artifact_files, "artifact_sha256": artifact_digest or "",
        "manifest_path": manifest_path.relative_to(ROOT).as_posix(),
    })
    archived = archive_attempt(attempt)
    print(json.dumps({
        "source_id": source_id, "project_root": project_root_value, "terminal_status": terminal,
        "dependency_exit_code": install["exit_code"] if install else None,
        "build_exit_code": build_result["exit_code"] if build_result else None,
        "source_mutations": len(mutations), "artifact_files": artifact_files,
        "dependencies_archived": bool(archived),
    }, sort_keys=True), flush=True)
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--command")
    parser.add_argument("--command-evidence")
    parser.add_argument("--node-profile")
    parser.add_argument("--dependency-manager", choices=("npm", "yarn", "corepack-yarn", "corepack-yarn3", "corepack-yarn331", "yarn2-immutable", "yarn3-immutable", "npm-force", "npm-unlocked", "yarn-unfrozen", "none"))
    parser.add_argument("--dependency-command")
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("--hydrate-submodules", action="store_true")
    parser.add_argument("--submodule-mirror", action="append", default=[])
    parser.add_argument("--swh-content", action="append", default=[])
    parser.add_argument("--hardhat-solc", action="append", default=[])
    args = parser.parse_args()
    environment_overrides = {}
    for item in args.env:
        if "=" not in item:
            parser.error("--env requires NAME=VALUE")
        name, value = item.split("=", 1)
        environment_overrides[name] = value
    submodule_mirrors = {}
    for item in args.submodule_mirror:
        if "=" not in item:
            parser.error("--submodule-mirror requires PATH=URL")
        relative, url = item.split("=", 1)
        if not relative or not url:
            parser.error("--submodule-mirror requires nonempty PATH=URL")
        submodule_mirrors[relative] = url
    if submodule_mirrors and not args.hydrate_submodules:
        parser.error("--submodule-mirror requires --hydrate-submodules")
    swh_contents = {}
    for item in args.swh_content:
        if "=" not in item:
            parser.error("--swh-content requires PATH=SHA1_GIT")
        relative, sha1_git = item.split("=", 1)
        if not relative or len(sha1_git) != 40:
            parser.error("--swh-content requires nonempty PATH and 40-character SHA1_GIT")
        swh_contents[relative] = sha1_git
    build(args.source_id, args.project_root, args.command, args.command_evidence, args.node_profile, args.dependency_manager, args.dependency_command, environment_overrides, args.hydrate_submodules, submodule_mirrors, swh_contents, args.hardhat_solc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
