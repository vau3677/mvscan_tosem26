#!/usr/bin/env python3
"""Best-effort no-edit Web3Bugs build executor with immutable attempt evidence."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import time
import uuid

from runners.common import ROOT, canonical_bytes, sha256_file, tree_digest

WEB3_SOURCE = ROOT / "benchmarks" / "sources" / "Web3Bugs" / "contracts"
POPULATION = ROOT / "benchmarks" / "web3bugs" / "population.csv"
EVIDENCE = ROOT / "benchmarks" / "web3bugs" / "build_evidence.json"
NODE_INVENTORY = ROOT / "environment" / "node_toolchain_inventory.json"
ATTEMPTS = ROOT / "benchmarks" / "web3bugs" / "best_effort_build_runs"
LEDGER = ROOT / "benchmarks" / "web3bugs" / "best_effort_build_attempts.csv"
TIMEOUT_SECONDS = 900
NODE_VERSIONS = {
    "node12-yarn1": "12.22.12",
    "node14-npm6": "14.21.3",
    "node14-yarn1": "14.21.3",
    "node16-npm8": "16.20.2",
    "node16-yarn1": "16.20.2",
    "node18-npm10": "18.20.8",
    "node18-yarn1": "18.20.8",
    "node22-npm10": "22.13.0",
    "node22-yarn1": "22.13.0",
}
LEDGER_FIELDS = (
    "attempt_id",
    "snapshot_id",
    "started_at",
    "duration_seconds",
    "dependency_command",
    "dependency_exit_code",
    "build_command",
    "build_exit_code",
    "terminal_status",
    "node_profile",
    "node_version",
    "source_files_checked",
    "source_mutations",
    "artifact_files",
    "artifact_sha256",
    "manifest_path",
)


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_state(root: Path) -> dict[str, dict[str, object]]:
    result = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not (path.is_file() or path.is_symlink()):
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            result[relative] = {
                "kind": "symlink",
                "target": target,
                "sha256": sha256_bytes(target.encode("utf-8")),
            }
        else:
            result[relative] = {
                "kind": "file",
                "byte_size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return result


def original_mutations(workspace: Path, baseline: dict[str, dict[str, object]]) -> list[str]:
    changed = []
    for relative, expected in baseline.items():
        path = workspace / relative
        if expected["kind"] == "symlink":
            if (
                not path.is_symlink()
                or os.readlink(path) != expected["target"]
            ):
                changed.append(relative)
        elif (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != expected["byte_size"]
            or sha256_file(path) != expected["sha256"]
        ):
            changed.append(relative)
    return changed


def profile_for(snapshot_id: str) -> tuple[str, str, str]:
    inventory = json.loads(NODE_INVENTORY.read_text(encoding="utf-8"))
    selection = next(
        row for row in inventory["snapshot_selections"]
        if row["snapshot_id"] == snapshot_id
    )
    profile = selection["profile"] or "node16-npm8"
    version = NODE_VERSIONS[profile]
    evidence = selection["selection_evidence"]
    if selection["profile"] is None:
        evidence += "; best-effort fallback to frozen node16-npm8"
    return profile, version, evidence


def project_root_candidates(
    workspace: Path,
    build_command: str,
) -> list[dict[str, object]]:
    values = shlex.split(build_command)
    executable = values[0] if values else ""
    script_name = values[2] if len(values) >= 3 and values[0] in {"npm", "yarn"} and values[1] == "run" else (
        values[1] if len(values) >= 2 and values[0] == "yarn" else None
    )
    candidates: dict[Path, str] = {}
    if script_name:
        for package in workspace.rglob("package.json"):
            if "node_modules" in package.parts:
                continue
            try:
                document = json.loads(package.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if script_name in document.get("scripts", {}):
                candidates[package.parent] = f"package.json script {script_name}"
    patterns = []
    if "hardhat" in values:
        patterns = ["hardhat.config.js", "hardhat.config.ts"]
    elif "truffle" in values:
        patterns = ["truffle-config.js", "truffle.js"]
    elif executable == "forge":
        patterns = ["foundry.toml"]
    elif executable == "brownie":
        patterns = ["brownie-config.yaml", "brownie-config.yml"]
    elif executable == "make":
        patterns = ["Makefile"]
    for pattern in patterns:
        for config in workspace.rglob(pattern):
            if "node_modules" not in config.parts:
                candidates.setdefault(config.parent, f"checked-in {pattern}")
    if not candidates:
        candidates[workspace] = "snapshot root fallback"
    result = []
    for candidate, evidence in candidates.items():
        solidity = [
            path for path in candidate.rglob("*.sol")
            if path.is_file() and "node_modules" not in path.parts
        ]
        standard = [
            path for directory in ("contracts", "src")
            for path in (candidate / directory).rglob("*.sol")
            if (candidate / directory).is_dir() and path.is_file()
        ]
        result.append({
            "relative_path": candidate.relative_to(workspace).as_posix() or ".",
            "evidence": evidence,
            "solidity_file_count": len(solidity),
            "standard_source_file_count": len(set(standard)),
            "depth": len(candidate.relative_to(workspace).parts),
        })
    return sorted(
        result,
        key=lambda row: (
            -int(row["standard_source_file_count"] > 0),
            -int(row["solidity_file_count"]),
            -int(row["depth"]),
            str(row["relative_path"]),
        ),
    )


def select_project_root(
    workspace: Path,
    build_command: str,
) -> tuple[Path, list[dict[str, object]]]:
    candidates = project_root_candidates(workspace, build_command)
    selected = workspace / str(candidates[0]["relative_path"])
    return selected, candidates


def clean_environment(
    attempt: Path,
    node_version: str,
) -> dict[str, str]:
    home = attempt / "home"
    temporary = attempt / "tmp"
    npm_cache = attempt / "npm-cache"
    yarn_cache = attempt / "yarn-cache"
    for path in (home, temporary, npm_cache, yarn_cache):
        path.mkdir(parents=True, exist_ok=True)
    node_bin = ROOT / "environment" / "toolchains" / "node" / node_version / "bin"
    yarn_bin = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin"
    foundry_bin = ROOT / "environment" / "toolchains" / "foundry-v1.5.1"
    environment = {
        "CI": "true",
        "FOUNDRY_DIR": str(attempt / "foundry"),
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_0": "git://github.com/",
        "GIT_CONFIG_KEY_1": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_1": "git@github.com:",
        "GIT_CONFIG_KEY_2": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_2": "ssh://git@github.com/",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HARDHAT_DISABLE_TELEMETRY_PROMPT": "true",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "NPM_CONFIG_CACHE": str(npm_cache),
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_AUDIT": "false",
        "PATH": f"{node_bin}:{yarn_bin}:{foundry_bin}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "YARN_CACHE_FOLDER": str(yarn_cache),
        "XDG_CACHE_HOME": str(attempt / "xdg-cache"),
        "XDG_CONFIG_HOME": str(attempt / "xdg-config"),
    }
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def dependency_command(
    workspace: Path,
    build_command: str,
    node_version: str,
) -> list[str] | None:
    package = workspace / "package.json"
    if not package.is_file():
        return None
    node_bin = ROOT / "environment" / "toolchains" / "node" / node_version / "bin"
    try:
        package_document = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        package_document = {}
    declared_manager = str(package_document.get("packageManager", "")).split("@", 1)[0]
    use_yarn = (
        declared_manager == "yarn"
        or (workspace / "yarn.lock").is_file()
        or (
            not (workspace / "package-lock.json").is_file()
            and build_command.startswith("yarn ")
        )
    )
    if use_yarn:
        yarn = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin" / "yarn.js"
        command = [
            str(node_bin / "node"), str(yarn), "install",
            "--non-interactive", "--ignore-scripts",
        ]
        if (workspace / "yarn.lock").is_file():
            command.append("--frozen-lockfile")
        return command
    npm = str(node_bin / "npm")
    command = [npm, "ci" if (workspace / "package-lock.json").is_file() else "install"]
    command.extend(["--no-audit", "--no-fund", "--ignore-scripts"])
    if node_version == "16.20.2":
        command.append("--legacy-peer-deps")
    return command


def executable_command(
    command: str,
    node_version: str,
) -> list[str]:
    values = shlex.split(command)
    if not values:
        raise ValueError("empty build command")
    node_bin = ROOT / "environment" / "toolchains" / "node" / node_version / "bin"
    if values[0] == "yarn":
        yarn = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin" / "yarn.js"
        return [str(node_bin / "node"), str(yarn), *values[1:]]
    if values[0] in {"npm", "npx"}:
        return [str(node_bin / values[0]), *values[1:]]
    if values[0] == "forge":
        return [
            str(ROOT / "environment" / "toolchains" / "foundry-v1.5.1" / "forge"),
            *values[1:],
        ]
    if values[0] == "brownie":
        brownie_python = ROOT / "environment" / "toolchains" / "brownie" / "bin" / "python"
        return [
            str(brownie_python),
            "-c",
            "from brownie._cli.__main__ import main; main()",
            *values[1:],
        ]
    return values


def run_command(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, object]:
    allowed = sorted(os.sched_getaffinity(0))
    cpus = set(allowed[:4])
    started = time.monotonic()
    timed_out = False
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except OSError as exc:
            stderr.write(f"{type(exc).__name__}: {exc}\n".encode("utf-8"))
            return {
                "command": command,
                "duration_seconds": time.monotonic() - started,
                "exit_code": None,
                "timed_out": False,
                "launch_error": f"{type(exc).__name__}: {exc}",
            }
        os.sched_setaffinity(process.pid, cpus)
        try:
            exit_code = process.wait(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                exit_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                exit_code = process.wait()
    return {
        "command": command,
        "cpu_affinity": sorted(cpus),
        "duration_seconds": time.monotonic() - started,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
    }


def artifact_state(workspace: Path) -> tuple[str | None, int, int]:
    selected = []
    for path in workspace.rglob("*"):
        if not (path.is_file() or path.is_symlink()):
            continue
        relative = path.relative_to(workspace)
        if "node_modules" in relative.parts:
            continue
        if any(
            part.lower() in {"build", "out"} or "artifact" in part.lower()
            for part in relative.parts
        ):
            selected.append(path)
    if not selected:
        return None, 0, 0
    return tree_digest(workspace, selected)


def write_manifest(path: Path, value: dict[str, object]) -> None:
    with path.open("xb") as stream:
        stream.write(canonical_bytes(value))


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


def build_snapshot(
    snapshot_id: str,
    command_override: str | None = None,
    command_evidence_override: str | None = None,
    project_root_override: str | None = None,
    dependency_manager_override: str | None = None,
    environment_overrides: dict[str, str] | None = None,
) -> Path:
    population = {row["snapshot_id"]: row for row in csv_rows(POPULATION)}
    if snapshot_id not in population:
        raise ValueError(f"unknown snapshot: {snapshot_id}")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    selected = next(row for row in evidence["snapshots"] if row["snapshot_id"] == snapshot_id)
    build_command = command_override or selected.get("selected_build_command")
    if not build_command:
        raise RuntimeError(f"snapshot {snapshot_id} has no frozen build command")
    if command_override and not command_evidence_override:
        raise ValueError("--command requires --command-evidence")
    if command_override:
        command_rank = "best_effort_derived"
        command_evidence = command_evidence_override
    else:
        command_rank = selected["selected_evidence_rank"]
        command_evidence = next(
            row["evidence"] for row in selected["build_command_candidates"]
            if row["command"] == build_command
            and row["rank"] == selected["selected_evidence_rank"]
        )

    started_at = dt.datetime.now(dt.timezone.utc)
    attempt_id = (
        f"web3bugs-{snapshot_id}-best-effort-"
        + started_at.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex
    )
    attempt = ATTEMPTS / snapshot_id / attempt_id
    attempt.mkdir(parents=True, exist_ok=False)
    workspace = attempt / "workspace"
    shutil.copytree(WEB3_SOURCE / snapshot_id, workspace, symlinks=True)
    baseline = file_state(workspace)
    baseline_path = attempt / "original_files.json"
    write_manifest(baseline_path, baseline)

    project_root, project_candidates = select_project_root(
        workspace, build_command
    )
    if project_root_override:
        requested_root = (workspace / project_root_override).resolve()
        if workspace.resolve() not in (requested_root, *requested_root.parents):
            raise ValueError("project root escapes snapshot workspace")
        if not requested_root.is_dir():
            raise ValueError(f"project root is not a directory: {project_root_override}")
        project_root = requested_root
    profile, node_version, node_evidence = profile_for(snapshot_id)
    environment = clean_environment(attempt, node_version)
    if environment_overrides:
        environment.update(environment_overrides)
    install_command = dependency_command(
        project_root, build_command, node_version
    )
    if dependency_manager_override == "none":
        install_command = None
    elif dependency_manager_override == "npm":
        npm = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "npm"
        install_command = [str(npm), "ci" if (project_root / "package-lock.json").is_file() else "install", "--no-audit", "--no-fund", "--ignore-scripts"]
        if node_version == "16.20.2":
            install_command.append("--legacy-peer-deps")
    elif dependency_manager_override == "npm-force":
        npm = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "npm"
        install_command = [str(npm), "ci" if (project_root / "package-lock.json").is_file() else "install", "--no-audit", "--no-fund", "--ignore-scripts", "--force"]
    elif dependency_manager_override == "yarn-unfrozen":
        node = ROOT / "environment" / "toolchains" / "node" / node_version / "bin" / "node"
        yarn = ROOT / "environment" / "toolchains" / "yarn" / "1.22.22" / "bin" / "yarn.js"
        install_command = [str(node), str(yarn), "install", "--non-interactive", "--ignore-scripts", "--pure-lockfile"]
    install = None
    if install_command is not None:
        install = run_command(
            install_command,
            project_root,
            environment,
            attempt / "dependency.stdout.log",
            attempt / "dependency.stderr.log",
        )
    can_build = (
        install is None
        or (install["exit_code"] == 0 and not install["timed_out"])
    )
    build = None
    if can_build:
        build = run_command(
            executable_command(build_command, node_version),
            project_root,
            environment,
            attempt / "build.stdout.log",
            attempt / "build.stderr.log",
        )
    mutations = original_mutations(workspace, baseline)
    artifact_digest, artifact_files, artifact_bytes = artifact_state(workspace)
    if install is not None and install["timed_out"]:
        terminal = "DEPENDENCY_TIMEOUT"
    elif install is not None and install["exit_code"] != 0:
        terminal = "DEPENDENCY_FAILURE"
    elif build is None:
        terminal = "BUILD_NOT_STARTED"
    elif build["timed_out"]:
        terminal = "BUILD_TIMEOUT"
    elif build["exit_code"] != 0:
        terminal = "BUILD_FAILURE"
    elif mutations:
        terminal = "PROHIBITED_EDIT"
    elif not artifact_digest:
        terminal = "SUCCESS_NO_ARTIFACTS"
    else:
        terminal = "SUCCESS"

    finished_at = dt.datetime.now(dt.timezone.utc)
    manifest = {
        "schema_version": 1,
        "attempt_id": attempt_id,
        "dataset": "web3bugs",
        "snapshot_id": snapshot_id,
        "source_commit": population[snapshot_id]["commit"],
        "source_population_sha256": population[snapshot_id]["snapshot_sha256"],
        "source_path": f"benchmarks/sources/Web3Bugs/contracts/{snapshot_id}",
        "workspace": workspace.relative_to(ROOT).as_posix(),
        "project_root": project_root.relative_to(workspace).as_posix() or ".",
        "project_root_candidates": project_candidates,
        "best_effort_deviation": {
            "exact_memory_limit_enforced": False,
            "swap_disabled": False,
            "network_enabled_for_dependency_acquisition_and_compiler_downloads": True,
            "cpu_affinity_count": 4,
            "authorization": "user explicitly authorized best-effort Web3Bugs builds",
        },
        "node_profile": profile,
        "node_version": node_version,
        "node_selection_evidence": node_evidence,
        "build_command_evidence_rank": command_rank,
        "build_command_evidence": command_evidence,
        "dependency": install,
        "dependency_manager_override": dependency_manager_override,
        "environment_overrides": environment_overrides or {},
        "build": build,
        "original_files_manifest": baseline_path.relative_to(ROOT).as_posix(),
        "original_file_count": len(baseline),
        "original_file_mutations": mutations,
        "artifact_sha256": artifact_digest,
        "artifact_file_count": artifact_files,
        "artifact_byte_size": artifact_bytes,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "terminal_status": terminal,
    }
    manifest_path = attempt / "attempt_manifest.json"
    write_manifest(manifest_path, manifest)
    append_ledger({
        "attempt_id": attempt_id,
        "snapshot_id": snapshot_id,
        "started_at": manifest["started_at"],
        "duration_seconds": manifest["duration_seconds"],
        "dependency_command": json.dumps(install["command"]) if install else "",
        "dependency_exit_code": install["exit_code"] if install else "",
        "build_command": build_command,
        "build_exit_code": build["exit_code"] if build else "",
        "terminal_status": terminal,
        "node_profile": profile,
        "node_version": node_version,
        "source_files_checked": len(baseline),
        "source_mutations": len(mutations),
        "artifact_files": artifact_files,
        "artifact_sha256": artifact_digest or "",
        "manifest_path": manifest_path.relative_to(ROOT).as_posix(),
    })
    print(json.dumps({
        "snapshot_id": snapshot_id,
        "attempt": manifest_path.relative_to(ROOT).as_posix(),
        "terminal_status": terminal,
        "project_root": project_root.relative_to(workspace).as_posix() or ".",
        "dependency_exit_code": install["exit_code"] if install else None,
        "build_exit_code": build["exit_code"] if build else None,
        "source_mutations": len(mutations),
        "artifact_files": artifact_files,
    }, sort_keys=True))
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--command")
    parser.add_argument("--command-evidence")
    parser.add_argument("--project-root")
    parser.add_argument("--dependency-manager", choices=("npm", "npm-force", "yarn-unfrozen", "none"))
    parser.add_argument("--env", action="append", default=[])
    args = parser.parse_args()
    environment_overrides = {}
    for item in args.env:
        if "=" not in item:
            parser.error("--env requires NAME=VALUE")
        name, value = item.split("=", 1)
        environment_overrides[name] = value
    build_snapshot(
        args.snapshot,
        args.command,
        args.command_evidence,
        args.project_root,
        args.dependency_manager,
        environment_overrides,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
