from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())

def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

def write_json_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_bytes(value))

def replace_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(canonical_bytes(value))
    os.replace(temporary, path)

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def tree_digest(root: Path, paths: Iterable[Path] | None = None) -> tuple[str, int, int]:
    selected = list(paths) if paths is not None else [p for p in root.rglob("*") if p.is_file() or p.is_symlink()]
    selected.sort(key=lambda p: p.relative_to(root).as_posix())
    digest = hashlib.sha256()
    count = byte_count = 0
    for path in selected:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        if path.is_symlink():
            data = b"SYMLINK\0" + os.readlink(path).encode("utf-8")
        elif path.is_file():
            data = path.read_bytes()
        else:
            continue
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        count += 1
        byte_count += len(data)
    return digest.hexdigest(), count, byte_count

def restore_hardhat_sources(workspace: Path) -> list[str]:
    """Restore missing compiler inputs from frozen Hardhat build-info files."""
    restored: set[str] = set()
    build_infos = sorted(workspace.glob("**/build-info/*.json"))
    if not build_infos:
        raise RuntimeError("Hardhat artifact mode requires frozen build-info")
    for build_info in build_infos:
        document = json.loads(build_info.read_text(encoding="utf-8"))
        sources = document.get("input", {}).get("sources", {})
        if not isinstance(sources, dict):
            raise RuntimeError(f"invalid Hardhat build-info sources: {build_info}")
        for logical, specification in sorted(sources.items()):
            relative = Path(logical)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise RuntimeError(f"unsafe Hardhat source path: {logical}")
            content = specification.get("content") if isinstance(specification, dict) else None
            if not isinstance(content, str):
                raise RuntimeError(f"Hardhat build-info source lacks content: {logical}")
            target = workspace / relative
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="")
            restored.add(relative.as_posix())
    return sorted(restored)

def restore_standard_json_sources(
    workspace: Path,
    input_path: str = "mvscan-standard-input.json",
) -> list[str]:
    """Materialize missing inline Standard JSON sources for Crytic Compile.

    Solc accepts fully inline sources, but Crytic Compile additionally verifies
    that every logical filename exists.  Restoring only missing files preserves
    the accepted checkout while making that filename validation deterministic.
    """
    document_path = workspace / input_path
    if not document_path.is_file():
        raise RuntimeError(f"Standard JSON input is missing: {input_path}")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    sources = document.get("sources", {})
    if not isinstance(sources, dict) or not sources:
        raise RuntimeError("Standard JSON input has no sources")
    restored = []
    for logical, specification in sorted(sources.items()):
        relative = Path(logical)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise RuntimeError(f"unsafe Standard JSON source path: {logical}")
        content = specification.get("content") if isinstance(specification, dict) else None
        if not isinstance(content, str):
            raise RuntimeError(f"Standard JSON source lacks inline content: {logical}")
        target = document_path.parent / relative
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")
        restored.append(target.relative_to(workspace).as_posix())
    return restored

def restore_brownie_sources(workspace: Path) -> list[str]:
    """Restore missing Solidity inputs embedded in frozen Brownie artifacts.

    Brownie stores the complete source text and its logical path in each
    ``build/contracts/*.json`` artifact.  Crytic Compile nevertheless requires
    those logical paths to exist on disk while reading the artifacts.  Accepted
    benchmark workspaces can omit dependency trees, so materialize only missing
    files and never replace checkout content.
    """
    restored: set[str] = set()
    artifacts = sorted(workspace.glob("**/build/contracts/*.json"))
    if not artifacts:
        raise RuntimeError("Brownie artifact mode requires frozen contract artifacts")
    for artifact in artifacts:
        document = json.loads(artifact.read_text(encoding="utf-8"))
        ast = document.get("ast")
        if not isinstance(ast, dict):
            continue
        logical = ast.get("absolutePath") or document.get("sourcePath")
        content = document.get("source")
        if not isinstance(logical, str) or not isinstance(content, str):
            continue
        relative = Path(logical)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise RuntimeError(f"unsafe Brownie source path: {logical}")
        target = workspace / relative
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")
        restored.add(relative.as_posix())
    return sorted(restored)

def normalize_brownie_artifact_paths(workspace: Path) -> list[str]:
    """Replace stale absolute Brownie source aliases with artifact-local paths.

    Brownie artifacts can retain the build machine's package-cache path in
    ``allSourcePaths`` and import AST nodes while the corresponding dependency
    artifact uses a portable ``deps/...`` path.  Source IDs let us derive the
    exact alias mapping without guessing or changing semantic AST fields.
    """
    artifacts = sorted(workspace.glob("**/build/contracts/*.json"))
    documents: dict[Path, dict[str, Any]] = {}
    aliases: dict[str, str] = {}
    for artifact in artifacts:
        document = json.loads(artifact.read_text(encoding="utf-8"))
        documents[artifact] = document
        ast = document.get("ast")
        if not isinstance(ast, dict):
            continue
        canonical = ast.get("absolutePath") or document.get("sourcePath")
        src = ast.get("src")
        paths = document.get("allSourcePaths")
        if not isinstance(canonical, str) or not isinstance(src, str) or not isinstance(paths, dict):
            continue
        source_id = src.rsplit(":", 1)[-1]
        stale = paths.get(source_id)
        if isinstance(stale, str) and stale != canonical:
            aliases[stale] = canonical

    def rewrite(value: Any) -> Any:
        if isinstance(value, str):
            return aliases.get(value, value)
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        return value

    changed = []
    for artifact, document in documents.items():
        normalized = rewrite(document)
        if normalized == document:
            continue
        artifact.write_text(json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="")
        changed.append(artifact.relative_to(workspace).as_posix())
    return changed

def build_artifact_state(workspace: Path) -> tuple[str | None, int, int]:
    selected = []
    for path in workspace.rglob("*"):
        if not (path.is_file() or path.is_symlink()):
            continue
        relative = path.relative_to(workspace)
        if "node_modules" in relative.parts:
            continue
        if any(part.lower() in {"build", "out"} or "artifact" in part.lower() for part in relative.parts):
            selected.append(path)
    if not selected:
        return None, 0, 0
    return tree_digest(workspace, selected)
