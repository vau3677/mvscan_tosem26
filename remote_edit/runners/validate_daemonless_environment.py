#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, shutil, subprocess, tempfile
from pathlib import Path
from runners.common import ROOT, canonical_bytes, sha256_file, tree_digest
from runners.configuration import load_named
from runners.run_mvscan import bwrap_command

def main():
    resource=json.loads((ROOT/"environment/resource_manifest.json").read_text())
    probe="""import json,os,resource,socket,subprocess
network_blocked=False
try: socket.getaddrinfo('example.com',80)
except OSError: network_blocked=True
root_read_only=False
try: open('/usr/mvscan-write-probe','w').write('x')
except OSError: root_read_only=True
out={'affinity':sorted(os.sched_getaffinity(0)),'rlimit_as':list(resource.getrlimit(resource.RLIMIT_AS)),'network_blocked':network_blocked,'root_read_only':root_read_only,'compiler_0_8_33_exists':os.path.isfile('/tmp/.svm/0.8.33/solc-0.8.33'),'node18':subprocess.check_output(['/opt/mvscan/node/18.20.8/bin/node','--version'],text=True).strip(),'node22':subprocess.check_output(['/opt/mvscan/node/22.13.0/bin/node','--version'],text=True).strip()}
print(json.dumps(out,sort_keys=True))"""
    with tempfile.TemporaryDirectory(prefix="mvscan-env-validation-",dir="/tmp") as td:
        d=Path(td); workspace=d/"workspace"; run=d/"run"; workspace.mkdir(); run.mkdir()
        shutil.copyfile(ROOT/"runners/container_exec.py",run/"container_exec.py")
        command=bwrap_command("",workspace,run,load_named("B0"),0,["/usr/local/bin/python","-c",probe])
        outer=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=120)
        metrics=json.loads((run/"process_metrics.json").read_text())
        observed=json.loads((run/"stdout.log").read_text())
    svm_digest,svm_files,svm_bytes=tree_digest(ROOT/"environment/oci-rootfs/opt/mvscan/svm")
    node18_digest,_,_=tree_digest(ROOT/"environment/oci-rootfs/opt/mvscan/node/18.20.8")
    node22_digest,_,_=tree_digest(ROOT/"environment/oci-rootfs/opt/mvscan/node/22.13.0")
    dependency_digest,dependency_files,dependency_bytes=tree_digest(ROOT/"environment/frozen_dependencies")
    external_compiler_digest,external_compiler_files,external_compiler_bytes=tree_digest(ROOT/"environment/frozen_compilers")
    patch_digest,patch_files,patch_bytes=tree_digest(ROOT/"environment/patches")
    base=json.loads((ROOT/"environment/oci_environment_manifest.json").read_text())
    extension={"base_oci_image_digest":base["image_digest"],"svm_tree_sha256":svm_digest,"svm_file_count":svm_files,"svm_byte_size":svm_bytes,"node18_tree_sha256":node18_digest,"node22_tree_sha256":node22_digest,"frozen_dependency_tree_sha256":dependency_digest,"frozen_dependency_file_count":dependency_files,"frozen_dependency_byte_size":dependency_bytes,"external_compiler_tree_sha256":external_compiler_digest,"external_compiler_file_count":external_compiler_files,"external_compiler_byte_size":external_compiler_bytes,"slither_patch_tree_sha256":patch_digest,"slither_patch_file_count":patch_files,"slither_patch_byte_size":patch_bytes,"resource_manifest_sha256":sha256_file(ROOT/"environment/resource_manifest.json"),"container_exec_sha256":sha256_file(ROOT/"runners/container_exec.py"),"run_mvscan_sha256":sha256_file(ROOT/"runners/run_mvscan.py"),"common_sha256":sha256_file(ROOT/"runners/common.py"),"subject_preparer_sha256":sha256_file(ROOT/"runners/prepare_subject_manifests.py")}
    runtime_digest="sha256:"+hashlib.sha256(canonical_bytes(extension)).hexdigest()
    valid=outer.returncode==0 and metrics["process_exit_code"]==0 and len(observed["affinity"])==resource["cpu_vcpus"] and observed["rlimit_as"]==[resource["memory_bytes"],resource["memory_bytes"]] and observed["network_blocked"] and observed["root_read_only"] and observed["compiler_0_8_33_exists"] and observed["node18"]=="v18.20.8" and observed["node22"]=="v22.13.0"
    report={"schema_version":1,"status":"COMPLETE" if valid else "BLOCKED_ENVIRONMENT","sandbox_backend":"bubblewrap-user-namespace","runtime_digest":runtime_digest,"extension":extension,"validation":observed,"resource_measurement":{"memory_peak_bytes":metrics.get("memory_peak_bytes"),"cgroup_memory_peak_bytes":metrics.get("cgroup_memory_peak_bytes")},"swap_note":"Host swap remains enabled; RLIMIT_AS caps subject address space at 32 GiB. Timing/resource-efficiency claims are excluded under the recorded deviation."}
    (ROOT/"environment/daemonless_environment_manifest.json").write_text(json.dumps(report,sort_keys=True,separators=(",",":"))+"\n")
    print(json.dumps({"status":report["status"],"runtime_digest":runtime_digest},sort_keys=True))
    return 0 if valid else 1
if __name__=="__main__": raise SystemExit(main())
