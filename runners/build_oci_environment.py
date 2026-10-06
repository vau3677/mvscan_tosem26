#!/usr/bin/env python3
"""Build and validate the frozen linux/amd64 OCI image without a Docker daemon."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

from runners.common import canonical_bytes, sha256_file, write_json_new

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = ROOT / "environment"
BASE_MANIFEST_PATH = ENVIRONMENT / "acquisition" / "oci-manifests-001" / "python-amd64-manifest.json"
BASE_MANIFEST_DIGEST = "sha256:6dafe336b64dbf76f7ec872d07e58b5c7de0e2ea5d4c0853a05c3b6be3278b00"
BASE_INDEX_DIGEST = "sha256:019e31cc1f52e4139d338bca44f27b71339a9da261738fd80fab9cf4595152fc"
BASE_BLOBS = ENVIRONMENT / "acquisition" / "oci-base-blobs-001"
ATTEMPT = ENVIRONMENT / "attempts" / "oci-build-002"
OCI_DESTINATION = ENVIRONMENT / "oci"
ROOTFS_DESTINATION = ENVIRONMENT / "oci-rootfs"
MANIFEST_DESTINATION = ENVIRONMENT / "oci_environment_manifest.json"
LOCK = ENVIRONMENT / "python.lock"
WHEELHOUSE = ENVIRONMENT / "wheelhouse"
FOUNDRY = ENVIRONMENT / "toolchains" / "foundry-v1.5.1"
FIXED_CREATED = "2026-08-14T00:00:00Z"


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return "sha256:" + sha256_file(path)


def blob_path(directory: Path, digest: str) -> Path:
    algorithm, value = digest.split(":", 1)
    if algorithm != "sha256" or len(value) != 64:
        raise ValueError(f"unsupported digest: {digest}")
    return directory / "sha256" / value


def registry_token() -> str:
    query = urllib.parse.urlencode(
        {"service": "registry.docker.io", "scope": "repository:library/python:pull"}
    )
    with urllib.request.urlopen(
        "https://auth.docker.io/token?" + query, timeout=60
    ) as response:
        return json.load(response)["token"]


def acquire_blob(digest: str, token: str) -> Path:
    destination = blob_path(BASE_BLOBS, digest)
    if destination.exists():
        if digest_file(destination) != digest:
            raise RuntimeError(f"cached blob hash mismatch: {digest}")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".partial")
    request = urllib.request.Request(
        "https://registry-1.docker.io/v2/library/python/blobs/" + digest,
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response, temporary.open("xb") as stream:
        shutil.copyfileobj(response, stream, length=1024 * 1024)
    if digest_file(temporary) != digest:
        raise RuntimeError(f"downloaded blob hash mismatch: {digest}")
    os.replace(temporary, destination)
    return destination


def install_custom_layer(layer_root: Path) -> dict[str, str]:
    layer_root.mkdir(parents=True)
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-index",
        f"--find-links={WHEELHOUSE}",
        "--require-hashes",
        "--no-deps",
        "--no-compile",
        "--root",
        str(layer_root),
        "--prefix",
        "/usr/local",
        "-r",
        str(LOCK),
    ]
    environment = {
        "HOME": str(ATTEMPT / "pip-home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    result = subprocess.run(command, env=environment, text=True, capture_output=True)
    (ATTEMPT / "pip.stdout.log").write_text(result.stdout, encoding="utf-8")
    (ATTEMPT / "pip.stderr.log").write_text(result.stderr, encoding="utf-8")
    (ATTEMPT / "pip.exit_code.txt").write_text(f"{result.returncode}\n", encoding="ascii")
    if result.returncode:
        raise RuntimeError("offline wheel installation failed")
    nested_prefix = layer_root / "usr" / "local" / "local"
    nested_scripts = nested_prefix / "bin"
    nested_packages = nested_prefix / "lib" / "python3.10" / "dist-packages"
    binary_directory = layer_root / "usr" / "local" / "bin"
    site_packages = layer_root / "usr" / "local" / "lib" / "python3.10" / "site-packages"
    if not nested_scripts.is_dir() or not nested_packages.is_dir():
        raise RuntimeError("unexpected host pip installation scheme")
    binary_directory.parent.mkdir(parents=True, exist_ok=True)
    site_packages.parent.mkdir(parents=True, exist_ok=True)
    os.replace(nested_scripts, binary_directory)
    os.replace(nested_packages, site_packages)
    shutil.rmtree(nested_prefix)
    for source in sorted(FOUNDRY.iterdir()):
        shutil.copyfile(source, binary_directory / source.name)
        (binary_directory / source.name).chmod(0o755)
    host_shebang = ("#!" + sys.executable).encode("utf-8")
    for path in sorted(binary_directory.iterdir()):
        if not path.is_file():
            continue
        data = path.read_bytes()
        first, separator, remainder = data.partition(b"\n")
        if first == host_shebang or (first.startswith(b"#!") and b"python" in first):
            path.write_bytes(b"#!/usr/local/bin/python\n" + remainder)
            path.chmod(0o755)
    provenance = layer_root / "opt" / "mvscan"
    provenance.mkdir(parents=True)
    for source in (
        LOCK,
        ENVIRONMENT / "python_artifacts.json",
        ENVIRONMENT / "foundry_manifest.json",
    ):
        shutil.copyfile(source, provenance / source.name)
    (layer_root / "workspace").mkdir()
    return {
        "pip_stdout_sha256": sha256_file(ATTEMPT / "pip.stdout.log"),
        "pip_stderr_sha256": sha256_file(ATTEMPT / "pip.stderr.log"),
    }


def deterministic_layer(root: Path, uncompressed: Path, compressed: Path) -> tuple[str, str, int]:
    def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        return info

    with tarfile.open(uncompressed, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            archive.add(
                path,
                arcname=path.relative_to(root).as_posix(),
                recursive=False,
                filter=normalize,
            )
    with uncompressed.open("rb") as source, compressed.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
    return digest_file(uncompressed), digest_file(compressed), compressed.stat().st_size


def write_blob_new(layout: Path, data: bytes) -> tuple[str, int]:
    digest = digest_bytes(data)
    destination = blob_path(layout / "blobs", digest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    return digest, len(data)


def apply_layer(rootfs: Path, path: Path) -> None:
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise RuntimeError(f"unsafe OCI layer member: {member.name}")
            basename = pure.name
            parent = rootfs.joinpath(*pure.parent.parts)
            if basename == ".wh..wh..opq":
                if parent.exists():
                    for child in parent.iterdir():
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                continue
            if basename.startswith(".wh."):
                target = parent / basename[4:]
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                elif target.exists() or target.is_symlink():
                    target.unlink()
                continue
            archive.extract(member, rootfs)


def validate_rootfs(rootfs: Path) -> dict[str, str]:
    commands = {
        "python": ["/usr/local/bin/python", "--version"],
        "slither": ["/usr/local/bin/slither", "--version"],
        "crytic_compile": ["/usr/local/bin/crytic-compile", "--version"],
        "forge": ["/usr/local/bin/forge", "--version"],
    }
    outputs = {}
    for name, command in commands.items():
        invocation = [
            "unshare",
            "--user",
            "--map-root-user",
            "chroot",
            str(rootfs),
            "/usr/bin/env",
            "-i",
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONHASHSEED=0",
            "TZ=UTC",
            *command,
        ]
        result = subprocess.run(invocation, text=True, capture_output=True)
        combined = (result.stdout + result.stderr).strip()
        (ATTEMPT / f"validate-{name}.log").write_text(combined + "\n", encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"{name} validation failed: {combined}")
        outputs[name] = combined
    expected = {
        "python": "Python 3.10.20",
        "slither": "0.11.3",
        "crytic_compile": "0.3.11",
        "forge": "1.5.1",
    }
    for name, version in expected.items():
        if version not in outputs[name]:
            raise RuntimeError(f"{name} version mismatch: {outputs[name]}")
    return outputs


def main() -> None:
    for path in (ATTEMPT, OCI_DESTINATION, ROOTFS_DESTINATION, MANIFEST_DESTINATION):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite: {path}")
    ATTEMPT.mkdir(parents=True)
    base_bytes = BASE_MANIFEST_PATH.read_bytes()
    if digest_bytes(base_bytes) != BASE_MANIFEST_DIGEST:
        raise RuntimeError("base platform manifest hash mismatch")
    base_manifest = json.loads(base_bytes)
    descriptors = [base_manifest["config"], *base_manifest["layers"]]
    token = registry_token()
    acquired = {descriptor["digest"]: acquire_blob(descriptor["digest"], token) for descriptor in descriptors}

    layer_root = ATTEMPT / "layer-root"
    pip_record = install_custom_layer(layer_root)
    uncompressed = ATTEMPT / "mvscan-layer.tar"
    compressed = ATTEMPT / "mvscan-layer.tar.gz"
    diff_id, layer_digest, layer_size = deterministic_layer(layer_root, uncompressed, compressed)

    base_config = json.loads(acquired[base_manifest["config"]["digest"]].read_bytes())
    base_config["created"] = FIXED_CREATED
    base_config.setdefault("rootfs", {}).setdefault("diff_ids", []).append(diff_id)
    base_config.setdefault("history", []).append(
        {
            "created": FIXED_CREATED,
            "created_by": "runners/build_oci_environment.py",
            "comment": "offline frozen MV-Scan Python and Foundry layer",
        }
    )
    image_config = base_config.setdefault("config", {})
    required_env = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "TZ": "UTC",
    }
    existing_env = {}
    for row in image_config.get("Env", []):
        key, _, value = row.partition("=")
        existing_env[key] = value
    existing_env.update(required_env)
    image_config["Env"] = [f"{key}={value}" for key, value in sorted(existing_env.items())]
    image_config["WorkingDir"] = "/workspace"
    image_config.setdefault("Labels", {}).update(
        {
            "org.opencontainers.image.title": "mvscan-frozen-evaluation",
            "org.opencontainers.image.version": "F1-20260814",
        }
    )

    layout = ATTEMPT / "oci-layout"
    (layout / "blobs" / "sha256").mkdir(parents=True)
    for descriptor in base_manifest["layers"]:
        destination = blob_path(layout / "blobs", descriptor["digest"])
        os.link(acquired[descriptor["digest"]], destination)
    custom_destination = blob_path(layout / "blobs", layer_digest)
    os.link(compressed, custom_destination)
    config_digest, config_size = write_blob_new(layout, canonical_bytes(base_config).rstrip(b"\n"))
    final_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            *base_manifest["layers"],
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": layer_size,
            },
        ],
        "annotations": {
            "org.opencontainers.image.ref.name": "mvscan-frozen:F1-20260814",
        },
    }
    manifest_digest, manifest_size = write_blob_new(
        layout, canonical_bytes(final_manifest).rstrip(b"\n")
    )
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest_size,
                "platform": {"architecture": "amd64", "os": "linux"},
                "annotations": {
                    "org.opencontainers.image.ref.name": "mvscan-frozen:F1-20260814"
                },
            }
        ],
    }
    (layout / "index.json").write_bytes(canonical_bytes(index))
    (layout / "oci-layout").write_bytes(
        canonical_bytes({"imageLayoutVersion": "1.0.0"})
    )

    rootfs = ATTEMPT / "rootfs"
    rootfs.mkdir()
    for descriptor in base_manifest["layers"]:
        apply_layer(rootfs, acquired[descriptor["digest"]])
    apply_layer(rootfs, compressed)
    validation = validate_rootfs(rootfs)
    binary_records = {}
    for name in ("python", "slither", "crytic-compile", "forge", "cast", "anvil", "chisel"):
        path = rootfs / "usr" / "local" / "bin" / name
        binary_records[name] = {
            "path": "/usr/local/bin/" + name,
            "sha256": sha256_file(path),
            "byte_size": path.stat().st_size,
        }

    manifest_record = {
        "schema_version": 1,
        "status": "COMPLETE",
        "architecture": "linux/amd64",
        "base_image": "docker.io/library/python:3.10.20-slim-bookworm",
        "base_index_digest": BASE_INDEX_DIGEST,
        "base_platform_manifest_digest": BASE_MANIFEST_DIGEST,
        "image_digest": manifest_digest,
        "config_digest": config_digest,
        "custom_layer_digest": layer_digest,
        "custom_layer_diff_id": diff_id,
        "dockerfile_sha256": sha256_file(ENVIRONMENT / "Dockerfile"),
        "python_lock_sha256": sha256_file(LOCK),
        "python_artifacts_manifest_sha256": sha256_file(
            ENVIRONMENT / "python_artifacts.json"
        ),
        "foundry_manifest_sha256": sha256_file(ENVIRONMENT / "foundry_manifest.json"),
        "pip_install": pip_record,
        "validation": validation,
        "binaries": binary_records,
        "resource_policy_manifest": "environment/resource_manifest.json",
        "runtime_validation_note": (
            "Root filesystem validated in a single-ID user namespace; Docker runtime "
            "enforcement remains blocked because host uidmap helpers are absent."
        ),
    }
    write_json_new(MANIFEST_DESTINATION, manifest_record)
    os.replace(layout, OCI_DESTINATION)
    os.replace(rootfs, ROOTFS_DESTINATION)
    print(
        json.dumps(
            {"image_digest": manifest_digest, "validation": validation},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
