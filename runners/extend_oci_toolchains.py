#!/usr/bin/env python3
"""Append all frozen project toolchains to the validated core OCI image."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

from runners.build_oci_environment import (
    apply_layer,
    blob_path,
    deterministic_layer,
    digest_file,
    write_blob_new,
)
from runners.common import ROOT, canonical_bytes, sha256_file, write_json_new

ENVIRONMENT = ROOT / "environment"
OLD_OCI = ENVIRONMENT / "oci"
OLD_ROOTFS = ENVIRONMENT / "oci-rootfs"
OLD_MANIFEST = ENVIRONMENT / "oci_environment_manifest.json"
OLD_ENVIRONMENT = ENVIRONMENT / "environment_manifest.json"
ATTEMPT = ENVIRONMENT / "attempts" / "oci-toolchains-001"
HISTORY = ENVIRONMENT / "oci_history"
NEW_OCI = ATTEMPT / "oci"
NEW_ROOTFS = ATTEMPT / "rootfs"
STAGING = ATTEMPT / "toolchain-layer"
COMPILER_INVENTORY = ENVIRONMENT / "compiler_inventory.json"
NODE_INVENTORY = ENVIRONMENT / "node_toolchain_inventory.json"


def copy_toolchains() -> None:
    targets = (
        (ENVIRONMENT / "toolchains" / "solc", STAGING / "opt" / "mvscan" / "solc"),
        (ENVIRONMENT / "toolchains" / "node", STAGING / "opt" / "mvscan" / "node"),
        (ENVIRONMENT / "toolchains" / "yarn", STAGING / "opt" / "mvscan" / "yarn"),
    )
    for source, destination in targets:
        shutil.copytree(source, destination, symlinks=True)
    provenance = STAGING / "opt" / "mvscan"
    shutil.copyfile(COMPILER_INVENTORY, provenance / "compiler_inventory.json")
    shutil.copyfile(NODE_INVENTORY, provenance / "node_toolchain_inventory.json")


def validate(rootfs: Path) -> dict[str, object]:
    compiler = json.loads(COMPILER_INVENTORY.read_text(encoding="utf-8"))
    node = json.loads(NODE_INVENTORY.read_text(encoding="utf-8"))
    versions = {}
    for record in compiler["compilers"]:
        command = ["/opt/mvscan/solc/" + record["version"] + "/solc", "--version"]
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "chroot", rootfs, *command],
            text=True,
            capture_output=True,
        )
        if result.returncode or record["version"] not in result.stdout + result.stderr:
            raise RuntimeError("chroot solc validation failed: " + record["version"])
        versions["solc-" + record["version"]] = (result.stdout + result.stderr).strip()
    for record in node["node_toolchains"]:
        command = ["/opt/mvscan/node/" + record["version"] + "/bin/node", "--version"]
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "chroot", rootfs, *command],
            text=True,
            capture_output=True,
        )
        if result.returncode or result.stdout.strip() != "v" + record["version"]:
            raise RuntimeError("chroot Node validation failed: " + record["version"])
        versions["node-" + record["version"]] = result.stdout.strip()
    yarn = node["yarn_toolchain"]
    node_path = "/opt/mvscan/node/16.20.2/bin/node"
    yarn_path = "/opt/mvscan/yarn/" + yarn["version"] + "/bin/yarn.js"
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "chroot", rootfs, node_path, yarn_path, "--version"],
        text=True,
        capture_output=True,
    )
    if result.returncode or result.stdout.strip() != yarn["version"]:
        raise RuntimeError("chroot Yarn validation failed")
    versions["yarn-" + yarn["version"]] = result.stdout.strip()
    return versions


def main() -> int:
    if ATTEMPT.exists() or HISTORY.exists():
        raise FileExistsError("refusing to overwrite OCI toolchain extension")
    ATTEMPT.mkdir(parents=True)
    old_record = json.loads(OLD_MANIFEST.read_text(encoding="utf-8"))
    old_index = json.loads((OLD_OCI / "index.json").read_text(encoding="utf-8"))
    old_descriptor = old_index["manifests"][0]
    if old_descriptor["digest"] != old_record["image_digest"]:
        raise RuntimeError("core OCI manifest identity mismatch")
    old_manifest_path = blob_path(OLD_OCI / "blobs", old_descriptor["digest"])
    old_image_manifest = json.loads(old_manifest_path.read_text(encoding="utf-8"))
    old_config_path = blob_path(OLD_OCI / "blobs", old_image_manifest["config"]["digest"])
    config = json.loads(old_config_path.read_text(encoding="utf-8"))

    copy_toolchains()
    uncompressed = ATTEMPT / "toolchains.tar"
    compressed = ATTEMPT / "toolchains.tar.gz"
    diff_id, layer_digest, layer_size = deterministic_layer(
        STAGING, uncompressed, compressed
    )
    shutil.copytree(OLD_OCI, NEW_OCI, copy_function=os.link)
    destination = blob_path(NEW_OCI / "blobs", layer_digest)
    os.link(compressed, destination)
    config["rootfs"]["diff_ids"].append(diff_id)
    config.setdefault("history", []).append({
        "created": "2026-08-14T00:00:00Z",
        "created_by": "runners/extend_oci_toolchains.py",
        "comment": "frozen Node Yarn and exact native-config solc toolchains",
    })
    config.setdefault("config", {}).setdefault("Labels", {})[
        "org.opencontainers.image.version"
    ] = "F1-20260814-toolchains"
    config_digest, config_size = write_blob_new(
        NEW_OCI, canonical_bytes(config).rstrip(b"\n")
    )
    new_manifest = {
        **old_image_manifest,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            *old_image_manifest["layers"],
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": layer_size,
            },
        ],
        "annotations": {
            "org.opencontainers.image.ref.name": "mvscan-frozen:F1-20260814-toolchains"
        },
    }
    image_digest, image_size = write_blob_new(
        NEW_OCI, canonical_bytes(new_manifest).rstrip(b"\n")
    )
    new_index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": image_digest,
            "size": image_size,
            "platform": {"architecture": "amd64", "os": "linux"},
            "annotations": {
                "org.opencontainers.image.ref.name": "mvscan-frozen:F1-20260814-toolchains"
            },
        }],
    }
    (NEW_OCI / "index.json").write_bytes(canonical_bytes(new_index))

    shutil.copytree(OLD_ROOTFS, NEW_ROOTFS, symlinks=True, copy_function=os.link)
    apply_layer(NEW_ROOTFS, compressed)
    validation = validate(NEW_ROOTFS)
    new_record = {
        **old_record,
        "image_digest": image_digest,
        "config_digest": config_digest,
        "toolchain_layer_digest": layer_digest,
        "toolchain_layer_diff_id": diff_id,
        "previous_core_image_digest": old_record["image_digest"],
        "dockerfile_sha256": sha256_file(ENVIRONMENT / "Dockerfile"),
        "compiler_inventory_sha256": sha256_file(COMPILER_INVENTORY),
        "node_toolchain_inventory_sha256": sha256_file(NODE_INVENTORY),
        "toolchain_validation": validation,
        "status": "COMPLETE",
        "runtime_validation_note": (
            "Core and toolchain root filesystem validated in a single-ID user namespace; "
            "container daemon unavailable because host uidmap helpers are absent."
        ),
    }
    new_manifest_path = ATTEMPT / "oci_environment_manifest.json"
    write_json_new(new_manifest_path, new_record)
    old_environment = json.loads(OLD_ENVIRONMENT.read_text(encoding="utf-8"))
    new_environment = {
        **old_environment,
        "immutable_oci_digest": image_digest,
        "oci_toolchains": {
            "compiler_inventory": "environment/compiler_inventory.json",
            "node_toolchain_inventory": "environment/node_toolchain_inventory.json",
        },
        "status": "BLOCKED_ENVIRONMENT",
        "unresolved": [
            "compiler selection for snapshots without an exact native declaration",
            "runtime resource-enforcement validation for build and analysis wrappers",
        ],
    }
    new_environment_path = ATTEMPT / "environment_manifest.json"
    write_json_new(new_environment_path, new_environment)

    HISTORY.mkdir()
    os.replace(OLD_OCI, HISTORY / "core-only-oci")
    os.replace(OLD_ROOTFS, HISTORY / "core-only-rootfs")
    os.replace(OLD_MANIFEST, HISTORY / "core-only-oci_environment_manifest.json")
    os.replace(OLD_ENVIRONMENT, HISTORY / "core-only-environment_manifest.json")
    os.replace(NEW_OCI, OLD_OCI)
    os.replace(NEW_ROOTFS, OLD_ROOTFS)
    os.replace(new_manifest_path, OLD_MANIFEST)
    os.replace(new_environment_path, OLD_ENVIRONMENT)
    print(json.dumps({
        "image_digest": image_digest,
        "previous_core_image_digest": old_record["image_digest"],
        "toolchain_validations": len(validation),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
