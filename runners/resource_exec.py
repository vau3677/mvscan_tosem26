#!/usr/bin/env python3
"""Run one chroot command with the frozen daemonless cgroup and namespace policy."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

from runners.common import ROOT

RESOURCE = ROOT / "environment" / "resource_manifest.json"


def parse_events(path: Path) -> dict[str, int]:
    result = {}
    for line in path.read_text(encoding="ascii").splitlines():
        name, value = line.split()
        result[name] = int(value)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--working-directory", default="/workspace")
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing command")
    if args.metrics.exists():
        raise FileExistsError(args.metrics)
    resource = json.loads(RESOURCE.read_text(encoding="utf-8"))
    timeout = args.timeout or resource["build_timeout_seconds"]
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < resource["cpu_vcpus"]:
        raise RuntimeError("fewer host CPUs available than the frozen allocation")
    cpus = set(allowed[:resource["cpu_vcpus"]])
    uid = os.getuid()
    parent = Path(
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    )
    cgroup = parent / ("mvscan-" + uuid.uuid4().hex)
    cgroup.mkdir()
    timed_out = False
    started = time.time()
    try:
        (cgroup / "memory.max").write_text(
            str(resource["memory_bytes"]), encoding="ascii"
        )
        (cgroup / "memory.swap.max").write_text("0", encoding="ascii")
        (cgroup / "pids.max").write_text("max", encoding="ascii")
        environment = {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
        invocation = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "chroot",
            str(args.rootfs.resolve()),
            "/usr/bin/env",
            "-i",
            *[f"{name}={value}" for name, value in sorted(environment.items())],
            "/usr/local/bin/python",
            "-c",
            (
                "import os,sys;"
                f"os.chdir({args.working_directory!r});"
                "os.execvp(sys.argv[1],sys.argv[1:])"
            ),
            *command,
        ]

        gated_invocation = [
            "/bin/sh",
            "-c",
            'kill -STOP $$; exec "$@"',
            "mvscan-resource-gate",
            *invocation,
        ]
        process = subprocess.Popen(
            gated_invocation,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stopped_pid, stopped_status = os.waitpid(process.pid, os.WUNTRACED)
        if stopped_pid != process.pid or not os.WIFSTOPPED(stopped_status):
            raise RuntimeError("resource child did not enter the enforcement gate")
        try:
            os.sched_setaffinity(process.pid, cpus)
            (cgroup / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
        except BaseException:
            os.kill(process.pid, signal.SIGKILL)
            process.wait()
            raise
        os.kill(process.pid, signal.SIGCONT)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        events = parse_events(cgroup / "memory.events")
        record = {
            "command": command,
            "container_invocation": invocation,
            "cpu_affinity": sorted(cpus),
            "cpu_count": len(cpus),
            "elapsed_seconds": time.time() - started,
            "exit_code": process.returncode,
            "memory_max_bytes": int((cgroup / "memory.max").read_text().strip()),
            "memory_peak_bytes": int((cgroup / "memory.peak").read_text().strip()),
            "memory_swap_max_bytes": int((cgroup / "memory.swap.max").read_text().strip()),
            "memory_swap_peak_bytes": int((cgroup / "memory.swap.peak").read_text().strip()),
            "network_namespace": "private_empty",
            "oom_killed": events.get("oom_kill", 0) > 0,
            "stderr": stderr,
            "stdout": stdout,
            "timed_out": timed_out,
            "timeout_seconds": timeout,
            "working_directory": args.working_directory,
        }
        args.metrics.parent.mkdir(parents=True, exist_ok=True)
        with args.metrics.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        if timed_out:
            return 124
        return process.returncode
    finally:
        for process_path in (cgroup / "cgroup.procs",):
            try:
                if process_path.read_text(encoding="ascii").strip():
                    raise RuntimeError("resource cgroup still contains a process")
            except FileNotFoundError:
                pass
        cgroup.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
