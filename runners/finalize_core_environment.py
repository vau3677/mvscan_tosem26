#!/usr/bin/env python3
"""Finalize exact non-project-specific package inventories for the frozen OCI image."""

from __future__ import annotations

import email.parser
import hashlib
import json
from pathlib import Path

from runners.common import sha256_file, tree_digest, write_json_new

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = ROOT / "environment"
ROOTFS = ENVIRONMENT / "oci-rootfs"
OCI_MANIFEST = ENVIRONMENT / "oci_environment_manifest.json"
OS_INVENTORY = ENVIRONMENT / "os_package_inventory.json"
PYTHON_INVENTORY = ENVIRONMENT / "installed_python_inventory.json"
ENVIRONMENT_MANIFEST = ENVIRONMENT / "environment_manifest.json"


def parse_dpkg_status(path: Path) -> list[dict[str, str]]:
    records = []
    parser = email.parser.Parser()
    for paragraph in path.read_text(encoding="utf-8").split("\n\n"):
        if not paragraph.strip():
            continue
        message = parser.parsestr(paragraph)
        if message.get("Status") != "install ok installed":
            continue
        records.append(
            {
                "package": message["Package"],
                "version": message["Version"],
                "architecture": message.get("Architecture", ""),
                "source": message.get("Source", ""),
            }
        )
    return sorted(records, key=lambda row: (row["package"], row["architecture"]))


def installed_python() -> tuple[list[dict[str, object]], str, int, int]:
    site = ROOTFS / "usr" / "local" / "lib" / "python3.10" / "site-packages"
    records = []
    for dist_info in sorted(site.glob("*.dist-info"), key=lambda path: path.name.lower()):
        metadata_path = dist_info / "METADATA"
        metadata = email.parser.BytesParser().parsebytes(metadata_path.read_bytes())
        digest, file_count, byte_size = tree_digest(dist_info)
        record_path = dist_info / "RECORD"
        records.append(
            {
                "name": metadata.get("Name"),
                "version": metadata.get("Version"),
                "dist_info": dist_info.name,
                "metadata_sha256": sha256_file(metadata_path),
                "record_sha256": sha256_file(record_path) if record_path.exists() else None,
                "dist_info_tree_sha256": digest,
                "dist_info_file_count": file_count,
                "dist_info_byte_size": byte_size,
            }
        )
    site_digest, site_file_count, site_byte_size = tree_digest(site)
    return records, site_digest, site_file_count, site_byte_size


def main() -> None:
    for destination in (OS_INVENTORY, PYTHON_INVENTORY, ENVIRONMENT_MANIFEST):
        if destination.exists():
            raise FileExistsError(f"refusing to overwrite: {destination}")
    oci = json.loads(OCI_MANIFEST.read_text(encoding="utf-8"))
    if oci.get("status") != "COMPLETE":
        raise RuntimeError("OCI environment is not complete")
    dpkg_status = ROOTFS / "var" / "lib" / "dpkg" / "status"
    packages = parse_dpkg_status(dpkg_status)
    metadata_root = ROOTFS / "var" / "lib" / "dpkg" / "info"
    metadata_files = [
        {
            "relative_path": path.relative_to(ROOTFS).as_posix(),
            "byte_size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(metadata_root.iterdir(), key=lambda item: item.name)
        if path.is_file()
    ]
    write_json_new(
        OS_INVENTORY,
        {
            "schema_version": 1,
            "base_platform_manifest_digest": oci["base_platform_manifest_digest"],
            "dpkg_status_sha256": sha256_file(dpkg_status),
            "installed_packages": packages,
            "dpkg_metadata_files": metadata_files,
        },
    )
    distributions, site_digest, site_files, site_bytes = installed_python()
    write_json_new(
        PYTHON_INVENTORY,
        {
            "schema_version": 1,
            "python": oci["validation"]["python"],
            "site_packages_tree_sha256": site_digest,
            "site_packages_file_count": site_files,
            "site_packages_byte_size": site_bytes,
            "distributions": distributions,
            "wheel_artifacts_manifest": "environment/python_artifacts.json",
            "wheel_artifacts_manifest_sha256": sha256_file(
                ENVIRONMENT / "python_artifacts.json"
            ),
        },
    )
    write_json_new(
        ENVIRONMENT_MANIFEST,
        {
            "schema_version": 1,
            "status": "BLOCKED_ENVIRONMENT",
            "architecture": "linux/amd64",
            "python": "3.10.20",
            "slither": "0.11.3",
            "crytic_compile": "0.3.11",
            "foundry": "v1.5.1",
            "timezone": "UTC",
            "locale": "C.UTF-8",
            "network": {"acquisition": "controlled_only", "analysis": "disabled"},
            "immutable_oci_digest": oci["image_digest"],
            "oci_layout": "environment/oci",
            "oci_manifest": "environment/oci_environment_manifest.json",
            "python_lock": "environment/python.lock",
            "python_artifacts": "environment/python_artifacts.json",
            "installed_python_inventory": "environment/installed_python_inventory.json",
            "os_package_inventory": "environment/os_package_inventory.json",
            "foundry_manifest": "environment/foundry_manifest.json",
            "resource_manifest": "environment/resource_manifest.json",
            "unresolved": [
                "project-compatible solc inventory and OCI inclusion",
                "project-compatible Node/package-manager inventory and OCI inclusion",
                "runtime resource-enforcement validation: host uidmap helpers absent",
            ],
        },
    )
    print(
        json.dumps(
            {
                "os_packages": len(packages),
                "dpkg_metadata_files": len(metadata_files),
                "python_distributions": len(distributions),
                "status": "BLOCKED_ENVIRONMENT",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
