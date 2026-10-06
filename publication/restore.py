#!/usr/bin/env python3
"""Restore byte-verified frozen artifacts from the publication release."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "publication/artifact-bundles.json").read_text())
CACHE = ROOT / "publication/data"

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

class Parts(io.RawIOBase):
    def __init__(self, paths):
        self.paths = iter(paths)
        self.current = None
    def readable(self):
        return True
    def read(self, size=-1):
        if size < 0:
            raise ValueError("bounded streaming reads required")
        output = bytearray()
        while len(output) < size:
            if self.current is None:
                try:
                    self.current = next(self.paths).open("rb")
                except StopIteration:
                    break
            block = self.current.read(size - len(output))
            if block:
                output.extend(block)
            else:
                self.current.close()
                self.current = None
        return bytes(output)
    def close(self):
        if self.current is not None:
            self.current.close()
        super().close()

def bundle_base_url():
    """Use explicit bundle hosting or the checkout's origin without embedding an account."""
    configured = os.environ.get("MVSCAN_BUNDLE_BASE_URL") or MANIFEST.get("download_base")
    if configured:
        return configured.rstrip("/") + "/"
    remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True)
    value = remote.stdout.strip()
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:")
    elif value.startswith("https://github.com/"):
        path = value.removeprefix("https://github.com/")
    else:
        raise RuntimeError("Set MVSCAN_BUNDLE_BASE_URL to the release download directory")
    path = path.removesuffix(".git").strip("/")
    if len(path.split("/")) != 2:
        raise RuntimeError("Set MVSCAN_BUNDLE_BASE_URL to the release download directory")
    return f"https://github.com/{path}/releases/download/{MANIFEST['release_tag']}/"

def assets(group, download):
    paths = []
    for entry in group["assets"]:
        path = ROOT / entry["name"] if entry.get("tracked") else CACHE / entry["name"]
        if not path.exists():
            if not download or entry.get("tracked"):
                raise RuntimeError(f"Missing {path}; use --download to fetch release assets")
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".download")
            url = bundle_base_url() + entry["name"]
            request = urllib.request.Request(url, headers={"User-Agent": "MV-Scan-publication"})
            try:
                with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                    shutil.copyfileobj(response, output)
                if temporary.stat().st_size != entry["bytes"] or sha256(temporary) != entry["sha256"]:
                    raise RuntimeError(f"Downloaded asset checksum mismatch: {entry['name']}")
                os.replace(temporary, path)
            finally:
                if temporary.exists():
                    temporary.unlink()
        if path.stat().st_size != entry["bytes"] or sha256(path) != entry["sha256"]:
            raise RuntimeError(f"Asset checksum mismatch: {path}")
        paths.append(path)
    return paths

def safe_path(root, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"Unsafe archive path: {name}")
    path = root.joinpath(*relative.parts)
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise RuntimeError(f"Archive path traverses a symlink outside its destination: {name}")
    return path

def extract(paths, root):
    root.mkdir(parents=True, exist_ok=True)
    with Parts(paths) as stream, tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            path = safe_path(root, member.name)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                if path.is_symlink() and os.readlink(path) == member.linkname:
                    continue
                if path.exists() or path.is_symlink():
                    raise RuntimeError(f"Refusing to overwrite {path}")
                target = Path(member.linkname)
                if target.is_absolute() or not (path.parent / target).resolve().is_relative_to(root.resolve()):
                    raise RuntimeError(f"Symlink escapes archive destination: {member.name}")
                path.symlink_to(member.linkname)
                continue
            if not (member.isfile() or member.islnk()):
                raise RuntimeError(f"Unsupported archive member: {member.name}")
            source = safe_path(root, member.linkname).open("rb") if member.islnk() else archive.extractfile(member)
            temporary = path.with_name(path.name + ".restore")
            try:
                with source, temporary.open("wb") as output:
                    shutil.copyfileobj(source, output)
                if path.exists() or path.is_symlink():
                    if path.is_symlink() or sha256(path) != sha256(temporary):
                        raise RuntimeError(f"Refusing to overwrite different content: {path}")
                else:
                    os.chmod(temporary, member.mode & 0o777)
                    os.replace(temporary, path)
            finally:
                if temporary.exists():
                    temporary.unlink()

def restore_file(group, download):
    paths = assets(group, download)
    destination = ROOT / group["destination"]
    if destination.exists():
        if sha256(destination) != group["sha256"]:
            raise RuntimeError(f"Existing file differs from frozen bytes: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".restore")
    try:
        source = gzip.open(paths[0], "rb") if group["kind"] == "gzip" else Parts(paths)
        with source, temporary.open("wb") as output:
            shutil.copyfileobj(source, output)
        if sha256(temporary) != group["sha256"]:
            raise RuntimeError(f"Restored file checksum mismatch: {destination}")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()

def runtime(download):
    if sys.platform != "linux":
        raise RuntimeError("Frozen detector execution requires Linux/amd64")
    for name, group in MANIFEST["groups"].items():
        if name.startswith("oci-"):
            restore_file(group, download)
    sys.path.insert(0, str(ROOT))
    from runners.build_oci_environment import apply_layer
    from runners.common import tree_digest
    destination = ROOT / "environment/oci-rootfs"
    expected = json.loads((ROOT / "environment/daemonless_environment_manifest.json").read_text())["extension"]
    checks = [("opt/mvscan/svm", "svm_tree_sha256"), ("opt/mvscan/node/18.20.8", "node18_tree_sha256"), ("opt/mvscan/node/22.13.0", "node22_tree_sha256")]
    if not destination.exists():
        temporary = ROOT / "environment/oci-rootfs.restore"
        if temporary.exists():
            raise RuntimeError(f"Previous incomplete restoration exists: {temporary}")
        temporary.mkdir()
        image = expected["base_oci_image_digest"].split(":")[1]
        blobs = ROOT / "environment/oci/blobs/sha256"
        if sha256(blobs / image) != image:
            raise RuntimeError("OCI image manifest checksum mismatch")
        manifest = json.loads((blobs / image).read_text())
        for layer in manifest["layers"]:
            path = blobs / layer["digest"].split(":")[1]
            if sha256(path) != layer["digest"].split(":")[1]:
                raise RuntimeError("OCI layer checksum mismatch")
            apply_layer(temporary, path)
        # The extension deliberately overlays generated base-image compiler trees.
        group = MANIFEST["groups"]["runtime-extension"]
        with Parts(assets(group, download)) as stream, tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                safe_path(temporary, member.name)
                archive.extract(member, temporary)
        for relative, key in checks:
            if tree_digest(temporary / relative)[0] != expected[key]:
                raise RuntimeError(f"Frozen runtime tree mismatch: {relative}")
        os.replace(temporary, destination)
    for relative, key in checks:
        if tree_digest(destination / relative)[0] != expected[key]:
            raise RuntimeError(f"Frozen runtime tree mismatch: {relative}")
    print("Frozen runtime extension hashes verified.")

def historical(download):
    """Restore ignored originals from the preserved Git commit without clobbering edits."""
    record = json.loads(gzip.decompress((ROOT / "publication/ignored-material.json.gz").read_bytes()))
    source = record["source_commit"]
    missing = []
    def matches(path, entry):
        if "target" in entry:
            return path.is_symlink() and os.readlink(path) == entry["target"]
        return path.is_file() and not path.is_symlink() and sha256(path) == entry["sha256"]
    for entry in record["files"]:
        path = safe_path(ROOT, entry["path"])
        if not path.exists() and not path.is_symlink():
            missing.append(entry["path"])
        elif not matches(path, entry):
            raise RuntimeError(f"Refusing to overwrite changed ignored file: {path}")
    if missing:
        available = subprocess.run(["git", "cat-file", "-e", source + "^{commit}"], cwd=ROOT, capture_output=True)
        if available.returncode:
            if not download:
                raise RuntimeError(f"Missing historical commit {source}; rerun with --download")
            subprocess.run(["git", "fetch", "origin", source], cwd=ROOT, check=True)
        pathspec = b"".join((":(literal)" + name).encode() + b"\0" for name in missing)
        subprocess.run(["git", "restore", "--source=" + source, "--worktree", "--pathspec-from-file=-", "--pathspec-file-nul"],
                       cwd=ROOT, input=pathspec, check=True)
    for entry in record["files"]:
        if not matches(safe_path(ROOT, entry["path"]), entry):
            raise RuntimeError(f"Historical restoration checksum mismatch: {entry['path']}")
    print(f"Verified {len(record['files'])} ignored originals; restored {len(missing)} missing files.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "tables", "inputs", "runtime", "historical"])
    parser.add_argument("--download", action="store_true", help="Fetch missing assets from the publication release")
    args = parser.parse_args()
    groups = MANIFEST["groups"]
    if args.action == "verify":
        for name, group in groups.items():
            assets(group, args.download)
            print("Verified", name)
    elif args.action == "tables":
        restore_file(groups["union-inventory"], args.download)
        subprocess.run([sys.executable, "-m", "runners.materialize_final_results", "--root", str(ROOT)], cwd=ROOT, check=True)
        subprocess.run([sys.executable, "-m", "runners.materialize_paper_tables"], cwd=ROOT, check=True)
    elif args.action == "inputs":
        for name in ["accepted-inputs", "source-evidence"]:
            extract(assets(groups[name], args.download), ROOT)
        print("Frozen inputs restored. See benchmarks/bundles/restoration-validation.json.")
    elif args.action == "historical":
        historical(args.download)
    else:
        runtime(args.download)

if __name__ == "__main__":
    main()
