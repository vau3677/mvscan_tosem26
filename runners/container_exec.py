#!/usr/bin/env python3
"""Container-side process wrapper with clean environment and cgroup peak memory."""

from __future__ import annotations

import argparse
import json
import os
import resource
from pathlib import Path
import signal
import subprocess
import time

CONFIG_NAMES = {
    "MVSCAN_STRICT_CONFIG",
    "MVSCAN_ABLATION",
    "MVSCAN_INCLUDE_SCALAR_WITNESSES",
    "MVSCAN_CONTEXTUAL_KEYS",
    "MVSCAN_INTERFACE_DISPATCH",
    "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS",
    "MVSCAN_ROOT_CONTEXT_SINKS",
    "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK",
    "MVSCAN_MAX_DISPATCH_TARGETS",
    "SINK_TEST",
    "DIVERGENCE_BUDGET",
    "NOOP_WRITE_FILTER",
    "REQUIRE_SAME_SLOT_KEY",
    "USER_CALLABLE_ALWAYS",
    "USER_CALLABLE_DENY",
    "ATOMIC_GROUP",
    "MERGE_OVERLOADS",
}
RUNTIME_NAMES = {
    "HOME",
    "ISD_JSON_OUT",
    "LANG",
    "LC_ALL",
    "MVSCAN_WORKING_DIRECTORY",
    "PATH",
    "PYTHONHASHSEED",
    "PYTHONPATH",
    "SVM_HOME",
    "TZ",
}


def sanitized_child_environment() -> dict[str, str]:
    """Return detector-visible variables, excluding wrapper-only controls."""
    return {
        name: os.environ[name]
        for name in sorted(CONFIG_NAMES | RUNTIME_NAMES)
        if name in os.environ and name != "MVSCAN_WORKING_DIRECTORY"
    }


def cgroup_memory_metrics() -> dict[str, int | bool | None]:
    result: dict[str, int | bool | None] = {
        "memory_peak_bytes": None,
        "oom_killed": False,
    }
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
        unified = next(line.split(":", 2)[2] for line in lines if line.startswith("0::"))
        cgroup = Path("/sys/fs/cgroup") / unified.lstrip("/")
        result["memory_peak_bytes"] = int(
            (cgroup / "memory.peak").read_text(encoding="ascii").strip()
        )
        events = {}
        for line in (cgroup / "memory.events").read_text(encoding="ascii").splitlines():
            name, value = line.split()
            events[name] = int(value)
        result["oom_killed"] = events.get("oom_kill", 0) > 0
    except (OSError, StopIteration, ValueError):
        pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing detector command")
    args.run_directory.mkdir(parents=True, exist_ok=True)
    stdout_path = args.run_directory / "stdout.log"
    stderr_path = args.run_directory / "stderr.log"
    metrics_path = args.run_directory / "process_metrics.json"
    clean_environment = sanitized_child_environment()
    started_wall = time.time()
    started_monotonic = time.monotonic()
    timed_out = False
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process_cwd = Path(os.environ.get("MVSCAN_WORKING_DIRECTORY", os.getcwd())).resolve()
        allowed_roots = (Path("/workspace"), Path("/tmp/analysis-input"))
        if not any(process_cwd == root or root in process_cwd.parents for root in allowed_roots):
            raise RuntimeError("execution working directory is outside an allowed sandbox mount")
        if not process_cwd.is_dir():
            raise RuntimeError("execution working directory is missing")
        process = subprocess.Popen(
            command,
            cwd=process_cwd,
            env=clean_environment,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                exit_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                exit_code = process.wait()
    finished_monotonic = time.monotonic()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    cgroup = cgroup_memory_metrics()
    resource_metrics = {
        "memory_peak_bytes": int(usage.ru_maxrss) * 1024,
        "cgroup_memory_peak_bytes": cgroup.get("memory_peak_bytes"),
        "oom_killed": (exit_code in {137, -9} and not timed_out),
    }
    record = {
        "command": command,
        "clean_environment": clean_environment,
        "elapsed_seconds": finished_monotonic - started_monotonic,
        "finished_epoch_seconds": time.time(),
        "process_exit_code": exit_code,
        "started_epoch_seconds": started_wall,
        "timed_out": timed_out,
        **resource_metrics,
    }
    with metrics_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return 124 if timed_out else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
