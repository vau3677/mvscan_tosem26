#!/usr/bin/env python3
"""Frozen MV-Scan runner. Benchmark execution is impossible before valid F1 sealing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.parse
import uuid

from runners.canonicalize_json import canonicalize
from runners.common import ROOT, build_artifact_state, canonical_bytes, normalize_brownie_artifact_paths, restore_brownie_sources, restore_hardhat_sources, restore_standard_json_sources, sha256_file, tree_digest, write_json_new
from runners.configuration import CONFIG_NAMES, load_named
from runners.validate_output import ValidationError, validate_run

RUNS = ROOT / "runs"
RESOURCE_MANIFEST = ROOT / "environment" / "resource_manifest.json"
ENVIRONMENT_MANIFEST = ROOT / "environment" / "environment_manifest.json"
F1_SEAL = ROOT / "freeze" / "F1_SEALED.json"
OCI_ROOTFS = ROOT / "environment" / "oci-rootfs"
SLITHER_CONVERT_PATCH = ROOT / "environment" / "patches" / "slither_convert.py"
SLITHER_SSA_PATCH = ROOT / "environment" / "patches" / "slither_ssa.py"
CONTAINER_WORKING_PATH = "/workspace"
CONTAINER_RUN_PATH = "/mnt"



def snapshot_digest(workspace: Path, relative_paths: list[str]) -> tuple[str, int, int]:
    selected = []
    for value in relative_paths:
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts or not value:
            raise RuntimeError("invalid snapshot path")
        path = workspace / relative
        if not path.is_file() and not path.is_symlink():
            raise RuntimeError("snapshot path missing: " + value)
        selected.append(path)
    return tree_digest(workspace, selected)

def component(value: str) -> str:
    return urllib.parse.quote(value, safe="._-")


def build_run_id(
    dataset: str,
    subject: str,
    revision_role: str,
    configuration: str,
    python_hash_seed: int,
    repetition: int,
) -> str:
    if configuration not in CONFIG_NAMES:
        raise ValueError(f"unknown configuration: {configuration}")
    if python_hash_seed < 0 or repetition < 1:
        raise ValueError("seed must be nonnegative and repetition must be positive")
    fields = (
        ("dataset", dataset),
        ("subject", subject),
        ("revision", revision_role),
        ("config", configuration),
        ("seed", str(python_hash_seed)),
        ("rep", str(repetition)),
    )
    if any(not value for _, value in fields):
        raise ValueError("run identifier fields must be nonempty")
    return "__".join(f"{name}={component(value)}" for name, value in fields)


def valid_f1_seal() -> bool:
    if not F1_SEAL.is_file():
        return False
    try:
        seal = json.loads(F1_SEAL.read_text(encoding="utf-8"))
        readiness_path = ROOT / "freeze" / "F1_readiness.json"
        readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if seal.get("status") != "F1_SEALED":
        return False
    if (
        readiness.get("all_requirements_complete") is not True
        or readiness.get("blocking_statuses") != []
        or sha256_file(readiness_path) != seal.get("readiness_sha256")
        or seal.get("f2_run_plan") != "freeze/F2_run_plan.json"
    ):
        return False
    try:
        from runners.check_f1 import dependencies as current_dependencies

        expected_dependencies = current_dependencies()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        return False
    return seal.get("dependencies") == expected_dependencies


def terminal_status(
    exit_code: int,
    timed_out: bool,
    stderr: str,
    oom_killed: bool,
) -> tuple[str, bool]:
    lowered = stderr.lower()
    context_bound = "max contexts" in lowered or "context bound" in lowered
    if timed_out:
        return "ANALYSIS_TIMEOUT", context_bound
    if oom_killed or exit_code in {137, -9}:
        return "OOM", context_bound
    if exit_code == 75:
        return "OTHER_FAILURE", context_bound
    if context_bound:
        return "CONTEXT_BOUND_FAILURE", True
    if exit_code != 0:
        return "ANALYSIS_FAILURE", False
    return "SUCCESS", False


def output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def write_text_new(path: Path, value: str) -> None:
    if path.exists():
        return
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(value)


def stop_timed_out_container(
    cid_path: Path,
    clean_host_environment: dict[str, str],
    run_directory: Path,
) -> dict[str, object]:
    record: dict[str, object] = {"attempted": False}
    try:
        cid = cid_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        record["error"] = str(exc)
        return record
    if not cid:
        record["error"] = "container ID file was empty"
        return record
    record.update({"attempted": True, "container_id": cid})
    try:
        result = subprocess.run(
            ["docker", "kill", cid],
            cwd=ROOT,
            env=clean_host_environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        write_text_new(run_directory / "docker.kill.stdout.log", result.stdout)
        write_text_new(run_directory / "docker.kill.stderr.log", result.stderr)
        record.update(
            {
                "exit_code": result.returncode,
                "stdout_sha256": sha256_file(run_directory / "docker.kill.stdout.log"),
                "stderr_sha256": sha256_file(run_directory / "docker.kill.stderr.log"),
            }
        )
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def apply_semantic_embargo(run_directory: Path) -> dict[str, object]:
    names = ("detector.json", "detector.canonical.json", "stdout.log", "stderr.log", "validation_failure.json")
    protected = []
    errors = []
    for name in names:
        path = run_directory / name
        if not path.exists():
            continue
        try:
            path.chmod(0)
            protected.append(name)
        except OSError as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
    return {"mode": "000", "protected_files": protected, "errors": errors, "applied": not errors}


def cleanup_workspace(workspace: Path) -> dict[str, object]:
    record: dict[str, object] = {"attempted": True, "removed": False}
    try:
        shutil.rmtree(workspace)
        record["removed"] = not workspace.exists()
    except OSError as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def write_failure_manifest(
    pending: dict[str, object],
    run_directory: Path,
    workspace: Path,
    started: float,
    terminal: str,
    error: BaseException,
    *,
    timed_out: bool = False,
    cleanup: dict[str, object] | None = None,
) -> None:
    try:
        source_digest_after, _, _ = snapshot_digest(workspace, list(pending.get("snapshot_paths", [])))
    except OSError:
        source_digest_after = None
    actual_inputs = dict(pending["expected_inputs"])
    actual_inputs["source_snapshot_sha256"] = source_digest_after
    workspace_cleanup = cleanup_workspace(workspace)
    stdout_path = run_directory / "stdout.log"
    stderr_path = run_directory / "stderr.log"
    docker_stdout_path = run_directory / "docker.stdout.log"
    docker_stderr_path = run_directory / "docker.stderr.log"
    metrics_path = run_directory / "process_metrics.json"
    detector_path = run_directory / "detector.json"
    final = {
        **pending,
        "actual_inputs": actual_inputs,
        "detector_json": "detector.json",
        "elapsed_seconds": time.time() - started,
        "peak_rss_bytes": None,
        "process_exit_code": None,
        "docker_exit_code": None,
        "timed_out": timed_out,
        "oom_killed": False,
        "context_bound_failure": False,
        "terminal_status": terminal,
        "failure_type": type(error).__name__,
        "failure_message": str(error),
        "cleanup": cleanup,
        "workspace_cleanup": workspace_cleanup,
        "pending_manifest_sha256": sha256_file(
            run_directory / "run_manifest.pending.json"
        ),
        "container_exec_sha256": sha256_file(run_directory / "container_exec.py"),
        "process_metrics_sha256": sha256_file(metrics_path)
        if metrics_path.is_file()
        else None,
        "docker_stdout_sha256": sha256_file(docker_stdout_path)
        if docker_stdout_path.is_file()
        else None,
        "docker_stderr_sha256": sha256_file(docker_stderr_path)
        if docker_stderr_path.is_file()
        else None,
        "stdout_sha256": sha256_file(stdout_path) if stdout_path.is_file() else None,
        "stderr_sha256": sha256_file(stderr_path) if stderr_path.is_file() else None,
        "raw_json_sha256": sha256_file(detector_path) if detector_path.is_file() else None,
        "canonical_json_sha256": None,
    }
    final["semantic_output_embargo"] = apply_semantic_embargo(run_directory)
    write_json_new(run_directory / "run_manifest.json", final)


def docker_command(
    image: str,
    workspace: Path,
    run_directory: Path,
    configuration: dict[str, str],
    seed: int,
    analysis_command: list[str],
) -> list[str]:
    resource = json.loads(RESOURCE_MANIFEST.read_text(encoding="utf-8"))
    command = [
        "flock",
        "--exclusive",
        "--nonblock",
        "--conflict-exit-code",
        "75",
        str(RUNS / ".analysis.lock"),
        "docker",
        "run",
        "--rm",
        "--cidfile",
        str(run_directory / "docker.cid"),
        "--platform",
        resource["architecture"],
        "--network",
        "none",
        "--cpus",
        str(resource["cpu_vcpus"]),
        "--memory",
        str(resource["memory_bytes"]),
        "--memory-swap",
        str(resource["memory_bytes"]),
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec",
        "--workdir",
        CONTAINER_WORKING_PATH,
        "--mount",
        f"type=bind,source={workspace},target={CONTAINER_WORKING_PATH}",
        "--mount",
        f"type=bind,source={run_directory},target={CONTAINER_RUN_PATH}",
    ]
    environment = dict(configuration)
    environment.update(
        {
            "HOME": "/tmp",
            "ISD_JSON_OUT": f"{CONTAINER_RUN_PATH}/detector.json",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONHASHSEED": str(seed),
            "TZ": "UTC",
        }
    )
    for name, value in sorted(environment.items()):
        command.extend(["--env", f"{name}={value}"])
    command.extend(
        [
            image,
            "/usr/local/bin/python",
            f"{CONTAINER_RUN_PATH}/container_exec.py",
            "--run-directory",
            CONTAINER_RUN_PATH,
            "--timeout",
            str(resource["analysis_timeout_seconds"]),
            "--",
            *analysis_command,
        ]
    )
    return command



def prepare_exact_solc_runtime(
    run_directory: Path,
    analysis_command: list[str],
    runtime_environment: dict[str, str] | None,
) -> dict[str, str]:
    """Make bare ``solc`` resolve to the command's exact frozen compiler.

    Crytic Compile's Standard JSON backend validates ``--solc`` but invokes a
    bare ``solc`` for compilation.  A run-local symlink keeps that backend on
    the exact frozen executable without modifying the immutable OCI rootfs.
    """
    runtime = dict(runtime_environment or {})
    if "--solc" not in analysis_command:
        return runtime
    index = analysis_command.index("--solc")
    if index + 1 >= len(analysis_command):
        raise RuntimeError("analysis command has --solc without an executable")
    exact_solc = analysis_command[index + 1]
    if not exact_solc.startswith("/tmp/.svm/"):
        raise RuntimeError("exact solc executable must be inside the frozen SVM mount")
    compiler_bin = run_directory / "compiler-bin"
    compiler_bin.mkdir()
    version=Path(exact_solc).parent.name
    frozen_in_rootfs=OCI_ROOTFS/"opt/mvscan/svm"/version/Path(exact_solc).name
    if frozen_in_rootfs.is_file():
        os.symlink(exact_solc, compiler_bin / "solc")
    else:
        external=ROOT/"environment/frozen_compilers"/version/Path(exact_solc).name
        if not external.is_file():
            raise RuntimeError(f"exact frozen solc binary is missing: {version}")
        shutil.copyfile(external,compiler_bin/"solc")
        os.chmod(compiler_bin/"solc",0o755)
        analysis_command[index+1]=f"{CONTAINER_RUN_PATH}/compiler-bin/solc"
    default_path = "/usr/local/bin:/usr/bin:/bin"
    runtime["PATH"] = (
        f"{CONTAINER_RUN_PATH}/compiler-bin:"
        + runtime.get("PATH", default_path)
    )
    return runtime


def bwrap_command(
    image: str,
    workspace: Path,
    run_directory: Path,
    configuration: dict[str, str],
    seed: int,
    analysis_command: list[str],
    runtime_environment: dict[str, str] | None = None,
) -> list[str]:
    """Build a daemonless, network-isolated invocation over the frozen OCI rootfs."""
    del image
    resource = json.loads(RESOURCE_MANIFEST.read_text(encoding="utf-8"))
    allowed_cpus = sorted(os.sched_getaffinity(0))
    if len(allowed_cpus) < resource["cpu_vcpus"]:
        raise RuntimeError("fewer host CPUs available than the frozen allocation")
    cpu_list = ",".join(str(value) for value in allowed_cpus[: resource["cpu_vcpus"]])
    environment = dict(configuration)
    runtime_environment = runtime_environment or {}
    if set(runtime_environment) - {"PATH", "FOUNDRY_OFFLINE", "FOUNDRY_SOLC", "MVSCAN_WORKING_DIRECTORY"}:
        raise ValueError("unsupported runtime environment override")
    environment.update({
        "HOME": "/tmp",
        "ISD_JSON_OUT": f"{CONTAINER_RUN_PATH}/detector.json",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": f"{CONTAINER_RUN_PATH}/detector",
        "PYTHONHASHSEED": str(seed),
        "SVM_HOME": "/opt/mvscan/svm",
        "TZ": "UTC",
    })
    environment.update(runtime_environment)
    invocation = [
        "flock", "--exclusive", "--nonblock", "--conflict-exit-code", "75",
        str(RUNS / ".analysis.lock"),
        "timeout", "--signal=TERM", "--kill-after=10s", f"{resource['analysis_timeout_seconds'] + 60}s",
        "prlimit", f"--as={resource['memory_bytes']}",
        "taskset", "--cpu-list", cpu_list,
        "bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
        "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--die-with-parent", "--ro-bind", str(OCI_ROOTFS), "/",
        "--ro-bind", str(SLITHER_CONVERT_PATCH), "/usr/local/lib/python3.10/site-packages/slither/slithir/convert.py",
        "--ro-bind", str(SLITHER_SSA_PATCH), "/usr/local/lib/python3.10/site-packages/slither/slithir/utils/ssa.py",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind", str(OCI_ROOTFS / "opt" / "mvscan" / "svm"), "/tmp/.svm",
        "--bind", str(workspace), CONTAINER_WORKING_PATH,
        "--bind", str(run_directory), CONTAINER_RUN_PATH,
    ]
    isolated_input = workspace / ".mvscan-input"
    if isolated_input.is_dir():
        invocation += ["--dir", "/tmp/analysis-input", "--bind", str(isolated_input), "/tmp/analysis-input"]
    invocation += [
        "--chdir", CONTAINER_WORKING_PATH,
        "/usr/bin/env", "-i",
        *[f"{name}={value}" for name, value in sorted(environment.items())],
        "/usr/local/bin/python", f"{CONTAINER_RUN_PATH}/container_exec.py",
        "--run-directory", CONTAINER_RUN_PATH,
        "--timeout", str(resource["analysis_timeout_seconds"]),
        "--", *analysis_command,
    ]
    return invocation

def execute(
    subject_manifest_path: Path,
    configuration_name: str,
    seed: int,
    repetition: int,
    fixture: bool,
) -> Path:
    subject = json.loads(subject_manifest_path.read_text(encoding="utf-8"))
    if not fixture and not valid_f1_seal():
        raise RuntimeError("benchmark execution refused: valid F1_SEALED artifact is absent")
    if fixture and subject.get("population_role") != "OUT_OF_POPULATION_FIXTURE":
        raise RuntimeError("fixture mode requires population_role=OUT_OF_POPULATION_FIXTURE")
    configuration = load_named(configuration_name)
    run_id = build_run_id(
        subject["dataset"],
        subject["subject_id"],
        subject["revision_role"],
        configuration_name,
        seed,
        repetition,
    )
    attempt_id = f"{run_id}__attempt={uuid.uuid4().hex}"
    run_directory = (RUNS / attempt_id).resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    source = (ROOT / subject["source_path"]).resolve()
    if ROOT not in source.parents or not source.is_dir():
        raise RuntimeError("subject source path must be a directory inside the project")
    workspace = run_directory / "workspace"
    subprocess.run(["cp", "-a", "--reflink=auto", str(source) + "/.", str(workspace)], check=True)
    artifact_digest, _, _ = build_artifact_state(workspace)
    if artifact_digest != subject["expected_inputs"]["build_sha256"]:
        raise RuntimeError("restored build artifact hash mismatch")
    if subject.get("restore_hardhat_sources_from_build_info", False):
        restore_hardhat_sources(workspace)
    if subject.get("normalize_brownie_artifact_paths", False):
        normalize_brownie_artifact_paths(workspace)
    if subject.get("restore_brownie_sources_from_artifacts", False):
        restore_brownie_sources(workspace)
    for relative, content in sorted(subject.get("workspace_overlays", {}).items()):
        overlay = Path(relative)
        if overlay.is_absolute() or ".." in overlay.parts or not relative:
            raise RuntimeError("invalid workspace overlay path")
        target = workspace / overlay
        if target.exists() or target.is_symlink():
            raise RuntimeError("workspace overlay refuses to replace existing path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content), encoding="utf-8", newline="")
    if subject.get("restore_standard_json_sources_from_overlay", False):
        standard_inputs=sorted(subject.get("workspace_overlays",{}))
        if len(standard_inputs)!=1:
            raise RuntimeError("direct-solc subject requires one Standard JSON overlay")
        restore_standard_json_sources(workspace,standard_inputs[0])
    shutil.copyfile(ROOT / "runners" / "container_exec.py", run_directory / "container_exec.py")
    detector_root = run_directory / "detector"
    detector_root.mkdir()
    shutil.copytree(ROOT / "mvscan-smoke" / "mvscan_plugin", detector_root / "mvscan_plugin", symlinks=True)
    shutil.copytree(ROOT / "mvscan-smoke" / "mvscan_slither_plugin.egg-info", detector_root / "mvscan_slither_plugin.egg-info", symlinks=True)
    snapshot_paths = list(subject["snapshot_paths"])
    source_digest_before, source_files, source_bytes = snapshot_digest(workspace, snapshot_paths)
    expected_source = subject["expected_inputs"]["source_snapshot_sha256"]
    if source_digest_before != expected_source:
        raise RuntimeError("restored source snapshot hash mismatch")

    environment = json.loads(ENVIRONMENT_MANIFEST.read_text(encoding="utf-8"))
    image = subject["image_reference"]
    analysis_command = list(subject["analysis_command"])
    runtime_environment = prepare_exact_solc_runtime(
        run_directory,
        analysis_command,
        dict(subject.get("runtime_environment", {})),
    )
    command = bwrap_command(
        image,
        workspace,
        run_directory,
        configuration,
        seed,
        analysis_command,
        runtime_environment,
    )
    pending = {
        "schema_version": 1,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "dataset": subject["dataset"],
        "subject": subject["subject_id"],
        "revision_role": subject["revision_role"],
        "configuration": configuration_name,
        "python_hash_seed": seed,
        "repetition": repetition,
        "command": command,
        "working_path": CONTAINER_WORKING_PATH,
        "sanitized_environment": {
            **configuration,
            "ISD_JSON_OUT": f"{CONTAINER_RUN_PATH}/detector.json",
            "PYTHONHASHSEED": str(seed),
        },
        "resource_limits": json.loads(RESOURCE_MANIFEST.read_text(encoding="utf-8")),
        "expected_inputs": subject["expected_inputs"],
        "snapshot_paths": snapshot_paths,
        "expected_compilation_units": subject["expected_compilation_units"],
        "restored_workspace": {
            "tree_sha256": source_digest_before,
            "file_count": source_files,
            "byte_size": source_bytes,
        },
        "environment_digest": environment.get("immutable_runtime_digest", environment["immutable_oci_digest"]),
    }
    write_json_new(run_directory / "run_manifest.pending.json", pending)
    clean_host_environment = {
        name: value
        for name, value in os.environ.items()
        if name in {"DOCKER_HOST", "PATH", "XDG_RUNTIME_DIR"}
    }
    started = time.time()
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=clean_host_environment,
            text=True,
            capture_output=True,
            timeout=pending["resource_limits"]["analysis_timeout_seconds"] + 60,
        )
    except subprocess.TimeoutExpired as exc:
        write_text_new(run_directory / "docker.stdout.log", output_text(exc.stdout))
        write_text_new(run_directory / "docker.stderr.log", output_text(exc.stderr))
        cleanup = stop_timed_out_container(
            run_directory / "docker.cid", clean_host_environment, run_directory
        )
        write_failure_manifest(
            pending,
            run_directory,
            workspace,
            started,
            "ANALYSIS_TIMEOUT",
            exc,
            timed_out=True,
            cleanup=cleanup,
        )
        return run_directory
    except Exception as exc:
        write_text_new(run_directory / "docker.stdout.log", "")
        write_text_new(
            run_directory / "docker.stderr.log",
            f"{type(exc).__name__}: {exc}\n",
        )
        write_failure_manifest(
            pending, run_directory, workspace, started, "OTHER_FAILURE", exc
        )
        return run_directory

    try:
        elapsed = time.time() - started
        write_text_new(run_directory / "docker.stdout.log", result.stdout)
        write_text_new(run_directory / "docker.stderr.log", result.stderr)
        metrics_path = run_directory / "process_metrics.json"
        metrics = (
            json.loads(metrics_path.read_text(encoding="utf-8"))
            if metrics_path.exists()
            else {}
        )
        stderr_path = run_directory / "stderr.log"
        stderr = (
            stderr_path.read_text(encoding="utf-8", errors="replace")
            if stderr_path.exists()
            else result.stderr
        )
        process_exit_code = metrics.get("process_exit_code")
        status_code = (
            process_exit_code
            if isinstance(process_exit_code, int)
            else result.returncode
        )
        oom_killed = bool(metrics.get("oom_killed"))
        process_timed_out = bool(metrics.get("timed_out")) or result.returncode == 124
        status, context_bound = terminal_status(
            status_code,
            process_timed_out,
            stderr,
            oom_killed,
        )
        source_digest_after, _, _ = snapshot_digest(workspace, list(pending.get("snapshot_paths", [])))
        actual_inputs = dict(subject["expected_inputs"])
        actual_inputs["source_snapshot_sha256"] = source_digest_after
        final = {
            **pending,
            "actual_inputs": actual_inputs,
            "detector_json": "detector.json",
            "elapsed_seconds": elapsed,
            "peak_rss_bytes": metrics.get("memory_peak_bytes"),
            "process_exit_code": process_exit_code,
            "docker_exit_code": result.returncode,
            "timed_out": process_timed_out,
            "oom_killed": oom_killed,
            "context_bound_failure": context_bound,
            "terminal_status": status,
            "pending_manifest_sha256": sha256_file(
                run_directory / "run_manifest.pending.json"
            ),
            "container_exec_sha256": sha256_file(
                run_directory / "container_exec.py"
            ),
            "process_metrics_sha256": sha256_file(metrics_path)
            if metrics_path.is_file()
            else None,
            "docker_stdout_sha256": sha256_file(
                run_directory / "docker.stdout.log"
            ),
            "docker_stderr_sha256": sha256_file(
                run_directory / "docker.stderr.log"
            ),
            "stdout_sha256": sha256_file(run_directory / "stdout.log")
            if (run_directory / "stdout.log").exists()
            else None,
            "stderr_sha256": sha256_file(stderr_path) if stderr_path.exists() else None,
            "raw_json_sha256": sha256_file(run_directory / "detector.json")
            if (run_directory / "detector.json").exists()
            else None,
            "canonical_json_sha256": None,
        }
        if status == "SUCCESS":
            try:
                validate_run(run_directory, manifest=final)
                final["canonical_json_sha256"] = canonicalize(
                    run_directory / "detector.json",
                    run_directory / "detector.canonical.json",
                )
            except (ValidationError, OSError, UnicodeError, ValueError) as exc:
                final["terminal_status"] = "PARSE_ACCEPTANCE_FAILURE"
                final["failure_type"] = type(exc).__name__
                final["failure_message"] = str(exc)
                write_json_new(
                    run_directory / "validation_failure.json",
                    {"status": "PARSE_ACCEPTANCE_FAILURE", "error": str(exc)},
                )
        final["workspace_cleanup"] = cleanup_workspace(workspace)
        final["semantic_output_embargo"] = apply_semantic_embargo(run_directory)
        write_json_new(run_directory / "run_manifest.json", final)
    except Exception as exc:
        if not (run_directory / "run_manifest.json").exists():
            write_failure_manifest(
                pending, run_directory, workspace, started, "OTHER_FAILURE", exc
            )
    return run_directory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("subject_manifest", type=Path)
    parser.add_argument("--configuration", choices=CONFIG_NAMES, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--out-of-population-fixture", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        raise SystemExit("execution requires explicit --execute")
    directory = execute(
        args.subject_manifest.resolve(),
        args.configuration,
        args.seed,
        args.repetition,
        args.out_of_population_fixture,
    )
    print(directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
