#!/usr/bin/env python3
"""Compile a complete source-only snapshot with an archived solc via Standard JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import posixpath
import re
import subprocess
import sys

PROJECT_ROOT = Path("/home/vau3677/liu_coop/anonymized_repo_TOSEM")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-dir", default=".")
    parser.add_argument("--include-path", action="append", default=[])
    parser.add_argument("--vendor-dir", action="append", default=[])
    parser.add_argument("--remapping", action="append", default=[])
    parser.add_argument("--exclude-dir", action="append", default=[])
    parser.add_argument("--optimizer", action="store_true")
    parser.add_argument("--optimizer-runs", type=int, default=200)
    parser.add_argument("--via-ir", action="store_true")
    args = parser.parse_args()
    compiler = PROJECT_ROOT / "environment" / "toolchains" / "solc" / args.version / "solc"
    if not compiler.is_file():
        raise SystemExit(f"archived compiler unavailable: {args.version}")
    root = Path.cwd()
    source_root = (root / args.source_dir).resolve()
    if root.resolve() not in (source_root, *source_root.parents) or not source_root.is_dir():
        raise SystemExit(f"invalid source directory: {args.source_dir}")
    sources = {}
    physical: dict[str, Path] = {}
    for path in sorted(source_root.rglob("*.sol")):
        relative = path.relative_to(root)
        excluded = {"node_modules", "build", "artifacts", "out", *args.exclude_dir}
        if any(part in excluded for part in relative.parts):
            continue
        key = relative.as_posix()
        sources[key] = {"content": path.read_text(encoding="utf-8", errors="replace")}
        physical[key] = path
    vendors = [(root / value).resolve() for value in args.vendor_dir]
    remappings = []
    for value in args.remapping:
        if "=" not in value:
            raise SystemExit(f"invalid remapping: {value}")
        prefix, target = value.split("=", 1)
        remappings.append((prefix.rstrip("/") + "/", (root / target).resolve()))
    imports = re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"']\s*;")
    queue = list(physical)
    while queue:
        key = queue.pop()
        path = physical[key]
        for imported in imports.findall(sources[key]["content"]):
            if imported.startswith("."):
                logical = posixpath.normpath(posixpath.join(posixpath.dirname(key), imported))
                candidate = (path.parent / imported).resolve()
            else:
                logical = posixpath.normpath(imported)
                candidate = None
                for prefix, target in remappings:
                    if imported.startswith(prefix):
                        option = (target / imported[len(prefix):]).resolve()
                        if option.is_file():
                            candidate = option
                            try:
                                logical = candidate.relative_to(root).as_posix()
                            except ValueError:
                                pass
                            break
                if candidate is None:
                    for vendor in vendors:
                        option = (vendor / imported).resolve()
                        if option.is_file():
                            candidate = option
                            break
                if candidate is None:
                    option = (root / imported).resolve()
                    if option.is_file():
                        candidate = option
            if logical in sources or candidate is None or not candidate.is_file():
                continue
            sources[logical] = {"content": candidate.read_text(encoding="utf-8", errors="replace")}
            physical[logical] = candidate
            queue.append(logical)
    if not sources:
        raise SystemExit("no Solidity sources")
    request = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "optimizer": {"enabled": args.optimizer, "runs": args.optimizer_runs},
            "viaIR": args.via_ir,
            "remappings": [
                f"{prefix}={target.relative_to(root).as_posix().rstrip('/')}/"
                for prefix, target in remappings
                if root.resolve() in (target, *target.parents)
            ],
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"], "": ["ast"]}},
        },
    }
    version_tuple = tuple(int(part) for part in args.version.split("."))
    command = [str(compiler), "--standard-json"]
    # --base-path was introduced after the 0.5.x compiler line. All sources in
    # this runner are already supplied inline in Standard JSON, so the older
    # compiler does not need filesystem import flags.
    if version_tuple >= (0, 6, 0):
        command.extend(["--base-path", str(root), "--allow-paths", str(root)])
    for value in args.include_path:
        include = (root / value).resolve()
        if root.resolve() not in (include, *include.parents):
            raise SystemExit(f"include path escapes workspace: {value}")
        command.extend(["--include-path", str(include)])
    process = subprocess.run(
        command,
        input=json.dumps(request, separators=(",", ":")).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    output_dir = root / "build" / "direct-solc"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "standard-input.json").write_text(json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    (output_dir / "standard-output.json").write_bytes(process.stdout)
    (output_dir / "compiler.stderr.log").write_bytes(process.stderr)
    try:
        response = json.loads(process.stdout)
    except json.JSONDecodeError:
        print(process.stderr.decode("utf-8", "replace"), file=sys.stderr)
        return process.returncode or 1
    errors = [item for item in response.get("errors", []) if item.get("severity") == "error"]
    print(json.dumps({"compiler": args.version, "source_files": len(sources), "compiler_errors": len(errors)}, sort_keys=True))
    for item in errors:
        print(item.get("formattedMessage", item.get("message", "compiler error")), file=sys.stderr)
    return 1 if process.returncode or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
