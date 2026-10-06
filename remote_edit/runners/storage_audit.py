#!/usr/bin/env python3
"""Compact, non-semantic storage audit for the frozen evaluation."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from runners.common import ROOT


def disk_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    result = subprocess.run(
        ["du", "-s", "--block-size=1", str(path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return int(result.stdout.split()[0])


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)]


def file_bytes(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def compress_probe(path: Path) -> dict[str, object]:
    original_mode = path.stat().st_mode & 0o777
    with tempfile.TemporaryDirectory(prefix="mvscan-storage-audit-", dir="/tmp") as directory:
        target = Path(directory) / (path.name + ".zst")
        started = time.monotonic()
        try:
            path.chmod(original_mode | 0o400)
            subprocess.run(
                ["zstd", "-1", "-q", "-f", str(path), "-o", str(target)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        finally:
            path.chmod(original_mode)
        source_size = path.stat().st_size
        compressed_size = target.stat().st_size
        return {
            "kind": path.name,
            "source_bytes": source_size,
            "zstd_level": 1,
            "compressed_bytes": compressed_size,
            "ratio": round(compressed_size / source_size, 5) if source_size else None,
            "seconds": round(time.monotonic() - started, 3),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compress", action="store_true")
    parser.add_argument("--compress-all", action="store_true")
    args = parser.parse_args()

    runs = ROOT / "runs"
    status_counts: Counter[str] = Counter()
    config_counts: Counter[str] = Counter()
    dataset_counts: Counter[str] = Counter()
    category_bytes: Counter[str] = Counter()
    raw_sizes: list[int] = []
    canonical_sizes: list[int] = []
    attempt_sizes: list[tuple[int, str, str, str]] = []
    terminal = 0
    incomplete = 0
    for attempt in sorted(runs.iterdir()) if runs.is_dir() else []:
        if not attempt.is_dir():
            continue
        manifest_path = attempt / "run_manifest.json"
        if not manifest_path.is_file():
            incomplete += 1
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        terminal += 1
        status_counts[str(manifest.get("terminal_status", "UNKNOWN"))] += 1
        config_counts[str(manifest.get("configuration", "UNKNOWN"))] += 1
        dataset_counts[str(manifest.get("dataset", "UNKNOWN"))] += 1
        for child in attempt.iterdir():
            if child.is_file():
                name = child.name
                if name == "detector.json":
                    category = "raw_detector_json"
                elif name == "detector.canonical.json":
                    category = "canonical_detector_json"
                elif name.endswith(".log"):
                    category = "logs"
                elif "manifest" in name or name.endswith(".json"):
                    category = "manifests_and_metadata"
                else:
                    category = "other_root_files"
                category_bytes[category] += file_bytes(child)
            elif child.is_dir():
                category_bytes["bundled_runner_or_detector"] += disk_bytes(child)
        raw = file_bytes(attempt / "detector.json")
        canonical = file_bytes(attempt / "detector.canonical.json")
        raw_sizes.append(raw)
        canonical_sizes.append(canonical)
        attempt_sizes.append((disk_bytes(attempt), manifest.get("dataset", "UNKNOWN"), manifest.get("subject", "UNKNOWN"), manifest.get("configuration", "UNKNOWN")))

    top_level = {}
    for name in ("benchmarks", "runs", "quarantine", "environment", "dataset", "oracle", ".git"):
        top_level[name] = disk_bytes(ROOT / name)

    accepted_attempts = set()
    for path in (ROOT / "benchmarks/subject_manifests").glob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        value = document.get("accepted_attempt_id")
        if isinstance(value, str):
            accepted_attempts.add(value)
    attempt_bytes: Counter[str] = Counter()
    attempt_component_bytes: Counter[str] = Counter()
    attempt_child_bytes: Counter[str] = Counter()
    attempt_statuses: dict[str, Counter[str]] = defaultdict(Counter)
    attempt_counts: Counter[str] = Counter()
    for dataset in ("isu", "web3bugs"):
        root = ROOT / "benchmarks" / dataset / "best_effort_build_runs"
        if not root.is_dir():
            continue
        for source_root in root.iterdir():
            if not source_root.is_dir():
                continue
            for attempt in source_root.iterdir():
                if not attempt.is_dir():
                    continue
                classification = "accepted" if attempt.name in accepted_attempts else "nonaccepted"
                size = disk_bytes(attempt)
                attempt_bytes[f"{dataset}_{classification}"] += size
                attempt_counts[f"{dataset}_{classification}"] += 1
                for child in attempt.iterdir():
                    if child.name == "workspace":
                        component = "workspace"
                    elif child.name == "home":
                        component = "isolated_home"
                    elif child.suffix.lower() in {".log"}:
                        component = "logs"
                    elif child.suffix.lower() in {".tar", ".tgz", ".gz", ".zst", ".zip"}:
                        component = "archives"
                    else:
                        component = "metadata_and_other"
                    attempt_component_bytes[f"{dataset}_{classification}_{component}"] += disk_bytes(child)
                    attempt_child_bytes[f"{dataset}_{classification}_{child.name}"] += disk_bytes(child)
                manifest = attempt / "attempt_manifest.json"
                status = "NO_MANIFEST"
                if manifest.is_file():
                    try:
                        status = str(json.loads(manifest.read_text(encoding="utf-8")).get("terminal_status", "UNKNOWN"))
                    except Exception:
                        status = "UNREADABLE"
                attempt_statuses[dataset][status] += 1

    compression = []
    if args.compress:
        candidates = []
        raw_paths = sorted(runs.glob("*/detector.json"), key=file_bytes)
        canonical_paths = sorted(runs.glob("*/detector.canonical.json"), key=file_bytes)
        for values in (raw_paths, canonical_paths):
            if values:
                candidates.append(values[-1])
                candidates.append(values[len(values) // 2])
        seen = set()
        for path in candidates:
            if path in seen or file_bytes(path) == 0:
                continue
            seen.add(path)
            compression.append(compress_probe(path))

    compression_inventory: Counter[str] = Counter()
    if args.compress_all:
        for kind, paths in (
            ("raw", sorted(runs.glob("*/detector.json"))),
            ("canonical", sorted(runs.glob("*/detector.canonical.json"))),
        ):
            for path in paths:
                original_mode = path.stat().st_mode & 0o777
                try:
                    path.chmod(original_mode | 0o400)
                    process = subprocess.Popen(
                        ["zstd", "-1", "-q", "-c", str(path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    compressed = 0
                    assert process.stdout is not None
                    while True:
                        chunk = process.stdout.read(1024 * 1024)
                        if not chunk:
                            break
                        compressed += len(chunk)
                    stderr = process.stderr.read() if process.stderr is not None else b""
                    if process.wait() != 0:
                        raise RuntimeError(stderr.decode("utf-8", errors="replace"))
                finally:
                    path.chmod(original_mode)
                compression_inventory[f"{kind}_source_bytes"] += path.stat().st_size
                compression_inventory[f"{kind}_compressed_bytes"] += compressed

    total_output = category_bytes["raw_detector_json"] + category_bytes["canonical_detector_json"]
    report = {
        "schema_version": 1,
        "launcher_paused": True,
        "filesystem": {
            "home": shutil.disk_usage(ROOT),
            "tmp": shutil.disk_usage("/tmp"),
        },
        "top_level_disk_bytes": top_level,
        "canonical_runs": {
            "terminal_attempts": terminal,
            "incomplete_attempts": incomplete,
            "statuses": dict(status_counts),
            "configurations": dict(config_counts),
            "datasets": dict(dataset_counts),
            "category_apparent_bytes": dict(category_bytes),
            "semantic_output_apparent_bytes": total_output,
            "raw_size_distribution": {
                "median": percentile(raw_sizes, 0.50),
                "p90": percentile(raw_sizes, 0.90),
                "p95": percentile(raw_sizes, 0.95),
                "maximum": max(raw_sizes, default=0),
            },
            "canonical_size_distribution": {
                "median": percentile(canonical_sizes, 0.50),
                "p90": percentile(canonical_sizes, 0.90),
                "p95": percentile(canonical_sizes, 0.95),
                "maximum": max(canonical_sizes, default=0),
            },
            "largest_attempts": [
                {"disk_bytes": size, "dataset": dataset, "subject": subject, "configuration": configuration}
                for size, dataset, subject, configuration in sorted(attempt_sizes, reverse=True)[:10]
            ],
        },
        "build_attempt_storage": {
            "disk_bytes": dict(attempt_bytes),
            "attempt_counts": dict(attempt_counts),
            "component_disk_bytes": dict(attempt_component_bytes),
            "largest_child_name_totals": [
                {"key": key, "disk_bytes": value}
                for key, value in attempt_child_bytes.most_common(30)
            ],
            "terminal_status_counts": {key: dict(value) for key, value in attempt_statuses.items()},
        },
        "compression_probes": compression,
        "compression_inventory": dict(compression_inventory),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
