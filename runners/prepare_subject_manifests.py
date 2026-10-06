#!/usr/bin/env python3
"""Discover structural compilation metadata and create frozen execution manifests.

Under Option B this script never reports or persists candidates, locations, counts,
or detector stdout/stderr. Raw detector JSON exists only in a temporary directory.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, posixpath, re, shutil, subprocess, tarfile, tempfile
from pathlib import Path
from runners.common import ROOT, build_artifact_state, normalize_brownie_artifact_paths, restore_brownie_sources, restore_hardhat_sources, restore_standard_json_sources, sha256_file, tree_digest
from runners.configuration import load_named
from runners.run_mvscan import bwrap_command, prepare_exact_solc_runtime

COHORT = ROOT / "benchmarks" / "execution_subjects.csv"
DEST = ROOT / "benchmarks" / "subject_manifests"
STATUS = ROOT / "reports" / "SUBJECT_MANIFEST_DISCOVERY.json"
FOUNDRY_OVERLAY = "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['lib']\n"
DIRECT_SOLC_DEPENDENCIES = {
    "27d99ecc930a40c3f443": [
        ("environment/frozen_dependencies/npm/openzeppelin-contracts-4.3.2.tgz", "node_modules/@openzeppelin/contracts"),
    ],
    "70": [
        ("environment/frozen_dependencies/npm/openzeppelin-contracts-4.3.2.tgz", "node_modules/@openzeppelin/contracts"),
    ],
    "2952c8154a7befc068f5": [
        ("environment/frozen_dependencies/npm/openzeppelin-contracts-4.0.0.tgz", "node_modules/@openzeppelin/contracts"),
        ("environment/frozen_dependencies/npm/uniswap-v2-core-1.0.1.tgz", "node_modules/@uniswap/v2-core"),
    ],
}
FOUNDRY_DEPENDENCIES = {
    "33438b4b2584abe90998": [("openzeppelin-contracts-4.9.3.tgz", "node_modules/@openzeppelin/contracts")],
    "55e1bbda13af0e5d9ef5": [("openzeppelin-contracts-4.9.6.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.9.6.tgz", "node_modules/@openzeppelin/contracts-upgradeable"), ("chainlink-contracts-0.8.0.tgz", "node_modules/@chainlink/contracts")],
    "57417c735ac666efab33": [("api3-airnode-protocol-0.14.1.tgz", "node_modules/@api3/airnode-protocol")],
    "7ac89b753c19d6b46c51": [("openzeppelin-contracts-4.9.3.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.9.3.tgz", "node_modules/@openzeppelin/contracts-upgradeable"), ("openzeppelin-contracts-5.0.1.tgz", "node_modules/@openzeppelin-v5/contracts"), ("chainlink-contracts-0.6.1.tgz", "node_modules/@chainlink/contracts"), ("solmate-6.2.0.tgz", "node_modules/solmate"), ("prb-math-4.0.1.tgz", "node_modules/@prb/math"), ("forge-std-1.7.4.tgz", "node_modules/forge-std"), ("ds-test-1.0.0.tgz", "node_modules/ds-test")],
    "9ae84cf683640be4e904": [("openzeppelin-contracts-4.8.0.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.8.0.tgz", "node_modules/@openzeppelin/contracts-upgradeable")],
    "af2962b8335feda2b275": [("openzeppelin-contracts-4.7.0.tgz", "node_modules/@openzeppelin/contracts"), ("jbx-protocol-juice-contracts-v3-2.0.0.tgz", "node_modules/@jbx-protocol/juice-contracts-v3"), ("paulrberg-contracts-3.7.0.tgz", "node_modules/@paulrberg/contracts"), ("prb-math-2.4.3.tgz", "node_modules/prb-math")],
    "b1eb5ae54e7312475c93": [("openzeppelin-contracts-4.7.2.tgz", "node_modules/@openzeppelin/contracts"), ("chainlink-contracts-0.4.2.tgz", "node_modules/@chainlink/contracts"), ("rari-capital-solmate-6.4.0.tgz", "node_modules/@rari-capital/solmate"), ("solidity-bytes-utils-0.8.0.tgz", "node_modules/solidity-bytes-utils")],
    "beef56a5a282f2ba6af8": [("openzeppelin-contracts-4.8.0.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.7.1.tgz", "node_modules/openzeppelin-upgradeable")],
    "bff4c70e313a4fd4754a": [("openzeppelin-contracts-4.8.0.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.8.0.tgz", "node_modules/@openzeppelin/contracts-upgradeable"), ("chainlink-contracts-0.5.1.tgz", "node_modules/@chainlink/contracts")],
    "106": [("openzeppelin-contracts-4.0.0.tgz", "node_modules/@openzeppelin/contracts"), ("rari-capital-solmate-6.2.0.tgz", "node_modules/@rari-capital/solmate"), ("base64-sol-1.0.1.tgz", "node_modules/base64-sol")],
    "191": [("openzeppelin-contracts-4.8.0.tgz", "node_modules/@openzeppelin/contracts"), ("openzeppelin-contracts-upgradeable-4.8.0.tgz", "node_modules/@openzeppelin/contracts-upgradeable"), ("chainlink-contracts-0.5.1.tgz", "node_modules/@chainlink/contracts")],
}

def node_version(toolchain: str) -> str:
    for value in ("12.22.12", "14.21.3", "16.20.2", "18.20.8", "22.13.0"):
        if toolchain.startswith("node" + value.split('.')[0]): return value
    return "16.20.2"

def direct_solc_strategy(source: Path, row: dict[str,str]):
    """Create a frozen Standard JSON input for accepted direct-solc builds."""
    build=row["build_command"]
    match=re.search(r"(?:--version\s+|/solc/)(\d+\.\d+\.\d+)",build)
    if not match:
        raise ValueError(f"direct solc version unavailable for {row['execution_subject_id']}")
    version=match.group(1)
    virtual={}
    for archive_name,target_root in DIRECT_SOLC_DEPENDENCIES.get(row["execution_subject_id"],[]):
        archive=ROOT/archive_name
        import_root=target_root[len("node_modules/"):] if target_root.startswith("node_modules/") else target_root
        with tarfile.open(archive,"r:gz") as package:
            for member in package.getmembers():
                if not member.isfile() or not member.name.startswith("package/") or not member.name.endswith(".sol"): continue
                extracted=package.extractfile(member)
                if extracted is None: continue
                relative=member.name[len("package/"):]
                content=extracted.read().decode("utf-8",errors="replace")
                virtual[posixpath.join(target_root,relative)]=content
                virtual[posixpath.join(import_root,relative)]=content
    existing=source/"build/direct-solc/standard-input.json"
    if existing.is_file():
        document=json.loads(existing.read_text(encoding="utf-8"))
    else:
        remappings=[]
        for value in re.findall(r"(?:^|\s)([^\s=]+=[^\s]+)",build):
            prefix,target=value.split("=",1)
            if prefix.startswith("@"): remappings.append((prefix.rstrip("/")+"/",target))
        root_values=re.findall(r"(?:^|\s)([A-Za-z0-9_@./*-]+\.sol)(?=\s|$)",build)
        roots=[]
        for value in root_values:
            matches=sorted(source.glob(value)) if "*" in value else [source/value]
            roots.extend(path for path in matches if path.is_file())
        if not roots:
            raise ValueError(f"direct solc roots unavailable for {row['execution_subject_id']}")
        imports=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"'][^;]*;")
        sources={}; physical={}; queue=[]
        for path in roots:
            key=path.relative_to(source).as_posix(); physical[key]=path; queue.append(key)
        while queue:
            key=queue.pop(); path=physical.get(key)
            if key in sources: continue
            text=virtual[key] if key in virtual else path.read_text(encoding="utf-8",errors="replace"); sources[key]={"content":text}
            for imported in imports.findall(text):
                if imported.startswith("."):
                    logical=posixpath.normpath(posixpath.join(posixpath.dirname(key),imported)); candidate=(path.parent/imported).resolve() if path is not None else None
                else:
                    logical=posixpath.normpath(imported); candidate=None
                    for prefix,target in remappings:
                        if imported.startswith(prefix):
                            option=(source/target/imported[len(prefix):]).resolve()
                            logical=posixpath.normpath(posixpath.join(target,imported[len(prefix):]))
                            if option.is_file(): candidate=option
                            break
                    if candidate is None:
                        option=(source/imported).resolve()
                        if option.is_file(): candidate=option
                if logical in virtual and logical not in sources:
                    queue.append(logical)
                elif candidate is not None and candidate.is_file() and logical not in sources:
                    physical[logical]=candidate; queue.append(logical)
        document={"language":"Solidity","sources":sources,"settings":{
          "optimizer":{"enabled":"--optimize" in build,"runs":200},
          "remappings":[f"{prefix}={target.rstrip('/')}/" for prefix,target in remappings],
          "outputSelection":{"*":{"*":["abi","metadata","devdoc","userdoc","evm.bytecode","evm.deployedBytecode"],"":["ast"]}}}}
    if virtual:
        imports=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"'][^;]*;")
        remappings=[]
        for value in document.get("settings",{}).get("remappings",[]) or []:
            if "=" in value: remappings.append(tuple(value.split("=",1)))
        queue=list(document["sources"])
        while queue:
            key=queue.pop(); text=document["sources"][key].get("content","")
            for imported in imports.findall(text):
                logical=posixpath.normpath(posixpath.join(posixpath.dirname(key),imported)) if imported.startswith(".") else posixpath.normpath(imported)
                if not imported.startswith("."):
                    for prefix,target in remappings:
                        if imported.startswith(prefix): logical=posixpath.normpath(posixpath.join(target,imported[len(prefix):])); break
                if logical not in document["sources"] and logical in virtual:
                    document["sources"][logical]={"content":virtual[logical]}; queue.append(logical)
    overlay=".mvscan-input/mvscan-standard-input.json"
    command=["slither","mvscan-standard-input.json","--detect","inconsistent_state","--fail-none","--compile-force-framework","solc-json","--solc",f"/tmp/.svm/{version}/solc-{version}","--foundry-ignore"]
    return "direct-solc",command,{overlay:json.dumps(document,sort_keys=True,separators=(",",":"))+"\n"}

def foundry_artifact_standard_json_strategy(source: Path, row: dict[str,str]):
    """Recreate Standard JSON from a frozen modern-Foundry artifact set."""
    candidates=[]
    for directory in sorted(source.glob("**/build-info")):
        if not directory.is_dir(): continue
        documents=[]
        for path in sorted(directory.glob("*.json")):
            document=json.loads(path.read_text(encoding="utf-8"))
            if "source_id_to_path" in document: documents.append(document)
        if documents: candidates.append((directory.parent,documents))
    if len(candidates)!=1:
        raise ValueError(f"unique modern Foundry artifact set unavailable for {row['execution_subject_id']}")
    artifact_root,build_infos=candidates[0]
    logical_paths=sorted({value for document in build_infos for value in document["source_id_to_path"].values()})
    if any(Path(value).is_absolute() or ".." in Path(value).parts for value in logical_paths):
        raise ValueError(f"unsafe modern Foundry source paths for {row['execution_subject_id']}")
    frozen_sources={}
    for archive_name,target_root in FOUNDRY_DEPENDENCIES.get(row["execution_subject_id"],[]):
        archive=ROOT/"environment/frozen_dependencies/npm"/archive_name
        with tarfile.open(archive,"r:gz") as package:
            for member in package.getmembers():
                if not member.isfile() or not member.name.startswith("package/") or not member.name.endswith(".sol"): continue
                extracted=package.extractfile(member)
                if extracted is not None: frozen_sources[posixpath.join(target_root,member.name[len("package/"):])]=extracted.read().decode("utf-8",errors="replace")
    available={}
    for logical in logical_paths:
        path=source/logical
        if path.is_file():
            available[logical]=path.read_text(encoding="utf-8",errors="replace")
        elif logical in frozen_sources:
            available[logical]=frozen_sources[logical]
        else:
            continue
    available.update(frozen_sources)
    versions=set(); normalized_settings={}; compilation_targets=set()
    for artifact in sorted(artifact_root.glob("**/*.json")):
        if artifact.parent.name=="build-info": continue
        try: raw=json.loads(artifact.read_text(encoding="utf-8")).get("rawMetadata")
        except (OSError,json.JSONDecodeError): continue
        if not raw: continue
        metadata=json.loads(raw); versions.add(metadata["compiler"]["version"].split("+")[0])
        settings=dict(metadata["settings"]); compilation_targets.update((settings.get("compilationTarget") or {}).keys()); settings.pop("compilationTarget",None)
        normalized_settings[json.dumps(settings,sort_keys=True,separators=(",",":"))]=settings
    if len(versions)!=1 or len(normalized_settings)!=1:
        raise ValueError(f"unique modern Foundry compiler/settings unavailable for {row['execution_subject_id']}")
    version=next(iter(versions)); settings=next(iter(normalized_settings.values()))
    foundry=(source/"foundry.toml").read_text(encoding="utf-8",errors="replace")
    src_match=re.search(r"(?m)^\s*src\s*=\s*['\"]([^'\"]+)['\"]",foundry)
    source_root=(src_match.group(1).strip("./") if src_match else "src").rstrip("/")+"/"
    remappings=[]
    for value in settings.get("remappings",[]) or []:
        if "=" in value:
            prefix,target=value.split("=",1); remappings.append((prefix.rsplit(":",1)[-1],target))
    imports=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"'][^;]*;")
    nonproduction={"test","tests","script","scripts","mock","mocks"}
    dependency_roots={"lib","node_modules","dependencies","deps",".cache"}
    selected={logical for logical in compilation_targets if logical in available and not (nonproduction & {part.lower() for part in Path(logical).parts}) and not (dependency_roots & {part.lower() for part in Path(logical).parts})}
    if not selected:
        selected={logical for logical in available if logical.startswith(source_root) and not (nonproduction & {part.lower() for part in Path(logical).parts}) and not (dependency_roots & {part.lower() for part in Path(logical).parts})}
    normalized_aliases={}
    for candidate in available:
        normalized_aliases.setdefault(posixpath.normpath(candidate),[]).append(candidate)
    queue=list(selected)
    while queue:
        key=queue.pop()
        for imported in imports.findall(available[key]):
            logical=posixpath.normpath(posixpath.join(posixpath.dirname(key),imported)) if imported.startswith(".") else posixpath.normpath(imported)
            if not imported.startswith("."):
                for prefix,target in sorted(remappings,key=lambda item:len(item[0]),reverse=True):
                    if imported.startswith(prefix): logical=target.rstrip("/")+"/"+imported[len(prefix):].lstrip("/"); break
            if logical not in available:
                aliases=normalized_aliases.get(posixpath.normpath(logical),[])
                if len(aliases)==1: logical=aliases[0]
            if logical in available and logical not in selected:
                selected.add(logical); queue.append(logical)
    sources={logical:{"content":available[logical]} for logical in sorted(selected)}
    settings["outputSelection"]={"*":{"*":["abi","metadata","devdoc","userdoc","evm.bytecode","evm.deployedBytecode"],"":["ast"]}}
    document={"language":"Solidity","sources":sources,"settings":settings}
    overlay=".mvscan-input/mvscan-standard-input.json"
    command=["slither","mvscan-standard-input.json","--detect","inconsistent_state","--fail-none","--compile-force-framework","solc-json","--solc",f"/tmp/.svm/{version}/solc-{version}","--foundry-ignore"]
    return "direct-solc",command,{overlay:json.dumps(document,sort_keys=True,separators=(",",":"))+"\n"}

def hardhat_standard_json_strategy(source: Path, row: dict[str,str]):
    """Recompile an accepted complete Hardhat build input with exact frozen solc."""
    documents=[]
    for path in sorted(source.glob("**/build-info/*.json")):
        document=json.loads(path.read_text(encoding="utf-8"))
        if "input" in document and "output" in document: documents.append(document)
    if len(documents)!=1:
        raise ValueError(f"unique Hardhat build input unavailable for {row['execution_subject_id']}")
    build_info=documents[0]; document=json.loads(json.dumps(build_info["input"]))
    version=build_info["solcVersion"].split("+")[0]
    document.setdefault("settings",{})["outputSelection"]={"*":{"*":["abi","metadata","devdoc","userdoc","evm.bytecode","evm.deployedBytecode"],"":["ast"]}}
    overlay=".mvscan-input/mvscan-standard-input.json"
    command=["slither","mvscan-standard-input.json","--detect","inconsistent_state","--fail-none","--compile-force-framework","solc-json","--solc",f"/tmp/.svm/{version}/solc-{version}","--foundry-ignore"]
    return "direct-solc",command,{overlay:json.dumps(document,sort_keys=True,separators=(",",":"))+"\n"}

def brownie_standard_json_strategy(source: Path, row: dict[str,str]):
    """Build one Solidity unit from frozen Brownie sources and package inputs."""
    specifications={
        "28": ("0.6.12",True,200,[],[]),
        "31": ("0.6.12",False,200,[("@openzeppelin/","deps/@openzeppelin/")],[]),
        "49": ("0.8.7",True,400,[],[("openzeppelin-contracts-4.3.2.tgz","@openzeppelin/contracts")]),
        "52": ("0.8.9",True,200,[],[("openzeppelin-contracts-4.3.2.tgz","@openzeppelin/contracts")]),
        "81": ("0.8.36",True,200,[],[("openzeppelin-contracts-4.4.2.tgz","@openzeppelin/contracts"),("openzeppelin-contracts-upgradeable-4.4.2.tgz","@openzeppelin-upgradeable/contracts")]),
        "131": ("0.8.10",True,200,[],[("openzeppelin-contracts-4.5.0.tgz","@openzeppelin/contracts"),("openzeppelin-contracts-upgradeable-4.5.0.tgz","@openzeppelin/contracts-upgradeable"),("smartcontractkit-chainlink-v1.4.0-contracts.tgz","@chainlink/contracts")]),
    }
    version,optimize,runs,remappings,archives=specifications[row["execution_subject_id"]]
    available={}
    excluded={"build","brownie","tests","test","scripts","script","node_modules",".git"}
    for path in source.rglob("*.sol"):
        logical=path.relative_to(source).as_posix()
        if excluded & set(Path(logical).parts): continue
        available[logical]=path.read_text(encoding="utf-8",errors="replace")
    for archive_name,target_root in archives:
        with tarfile.open(ROOT/"environment/frozen_dependencies/npm"/archive_name,"r:gz") as package:
            for member in package.getmembers():
                if not member.isfile() or not member.name.startswith("package/") or not member.name.endswith(".sol"): continue
                extracted=package.extractfile(member)
                if extracted is not None:
                    relative=member.name[len("package/"):]; content=extracted.read().decode("utf-8",errors="replace")
                    available[posixpath.join(target_root,relative)]=content
                    if target_root=="@chainlink/contracts":
                        for prefix in ("src/v0.8/","contracts/src/v0.8/"):
                            if relative.startswith(prefix): available[posixpath.join(target_root,relative[len(prefix):])]=content
    imports=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"'][^;]*;")
    nonproduction={"test","tests","script","scripts","mock","mocks","testing","stubs"}
    selected=set()
    for artifact in source.glob("**/build/contracts/*.json"):
        try: artifact_document=json.loads(artifact.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError): continue
        artifact_version=str((artifact_document.get("compiler") or {}).get("version") or "")
        if not artifact_version.startswith(version): continue
        logical=(artifact_document.get("ast") or {}).get("absolutePath") or artifact_document.get("sourcePath")
        if isinstance(logical,str) and logical.startswith("project:/"): logical=logical[len("project:/"):]
        if isinstance(logical,str) and logical in available and not (nonproduction & {part.lower() for part in Path(logical).parts}): selected.add(logical)
    if not selected:
        selected={key for key in available if key.startswith("contracts/") and not (nonproduction & {part.lower() for part in Path(key).parts})}
    queue=list(selected)
    while queue:
        key=queue.pop()
        for imported in imports.findall(available[key]):
            logical=posixpath.normpath(posixpath.join(posixpath.dirname(key),imported)) if imported.startswith(".") else posixpath.normpath(imported)
            if not imported.startswith("."):
                for prefix,target in remappings:
                    if imported.startswith(prefix): logical=posixpath.normpath(posixpath.join(target,imported[len(prefix):])); break
            if logical in available and logical not in selected:
                selected.add(logical); queue.append(logical)
    settings={"optimizer":{"enabled":optimize,"runs":runs},"remappings":[f"{prefix}={target}" for prefix,target in remappings],"outputSelection":{"*":{"*":["abi","metadata","devdoc","userdoc","evm.bytecode","evm.deployedBytecode"],"":["ast"]}}}
    if row["execution_subject_id"] in {"49","131"}: settings["evmVersion"]="london"
    document={"language":"Solidity","sources":{key:{"content":available[key]} for key in sorted(selected)},"settings":settings}
    overlay=".mvscan-input/mvscan-standard-input.json"
    command=["slither","mvscan-standard-input.json","--detect","inconsistent_state","--fail-none","--compile-force-framework","solc-json","--solc",f"/tmp/.svm/{version}/solc-{version}","--foundry-ignore"]
    return "direct-solc",command,{overlay:json.dumps(document,sort_keys=True,separators=(",",":"))+"\n"}

def strategy(source: Path, row: dict[str,str]):
    names={p.name for p in source.iterdir()}
    overlays={}
    command=["slither", ".", "--detect", "inconsistent_state", "--fail-none"]
    build_info_documents=[]
    for path in source.glob("**/build-info/*.json"):
        try: build_info_documents.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError,json.JSONDecodeError): pass
    has_hardhat_build_info=any("input" in value and "output" in value for value in build_info_documents)
    has_foundry_build_info=any("source_id_to_path" in value for value in build_info_documents)
    if row.get("dataset")=="web3bugs" and row["execution_subject_id"] in {"28","31","49","52","81","131"}:
        kind,command,overlays=brownie_standard_json_strategy(source,row)
    elif row.get("execution_subject_id") in {"3b078676f7225dc450dc","f50077300d555dbf4ab9"}:
        kind,command,overlays=hardhat_standard_json_strategy(source,row)
    elif "direct_solc_build.py" in row["build_command"] or re.match(r"^\S*/solc/\d+\.\d+\.\d+/solc(?:\s|$)",row["build_command"]):
        kind,command,overlays=direct_solc_strategy(source,row)
    elif "brownie" in row["build_command"]:
        command += ["--compile-force-framework", "brownie", "--brownie-ignore-compile"]
        kind="brownie"
    elif "truffle" in row["build_command"]:
        command += ["--compile-force-framework", "truffle", "--truffle-ignore-compile"]
        kind="truffle"
    elif has_hardhat_build_info:
        command += ["--compile-force-framework", "hardhat", "--hardhat-ignore-compile", "--npx-disable"]
        artifact_directories=sorted({path.parent.relative_to(source).as_posix() for path in source.glob("**/build-info") if path.is_dir() and any("input" in value and "output" in value for value in [json.loads(item.read_text(encoding="utf-8")) for item in path.glob("*.json")])})
        if "artifacts" not in artifact_directories and len(artifact_directories)==1:
            command += ["--hardhat-artifacts-directory",artifact_directories[0]]
        kind="hardhat"
    elif "foundry.toml" in names:
        try:
            kind,command,overlays=foundry_artifact_standard_json_strategy(source,row)
        except ValueError:
            command += ["--compile-force-framework", "foundry", "--foundry-ignore-compile"]
            artifact_directories=sorted({path.parent.relative_to(source).as_posix() for path in source.glob("**/build-info") if path.is_dir()})
            if "out" not in artifact_directories and len(artifact_directories)==1:
                command += ["--foundry-out-directory",artifact_directories[0]]
            kind="foundry"
    elif ".dapprc" in names:
        overlays["foundry.toml"]=FOUNDRY_OVERLAY
        command += ["--compile-force-framework", "foundry"]
        kind="dapp-via-foundry"
    elif any(name.startswith("hardhat.config") for name in names):
        config=next((name for name in sorted(names) if name.startswith("hardhat.config")),None)
        command += ["--compile-force-framework", "hardhat", "--hardhat-ignore-compile", "--npx-disable"]
        artifact_directories=sorted({path.parent.relative_to(source).as_posix() for path in source.glob("**/build-info") if path.is_dir()})
        if "artifacts" not in artifact_directories and len(artifact_directories)==1:
            command += ["--hardhat-artifacts-directory",artifact_directories[0]]
        if "--config" in row["build_command"]:
            parts=row["build_command"].split(); command += ["--hardhat-config-file", parts[parts.index("--config")+1]]
        kind="hardhat"
    elif "brownie-config.yaml" in names or "brownie-config.yml" in names:
        command += ["--compile-force-framework", "brownie", "--brownie-ignore-compile"]
        kind="brownie"
    elif "truffle-config.js" in names or "truffle.js" in names:
        command += ["--compile-force-framework", "truffle", "--truffle-ignore-compile"]
        kind="truffle"
    else:
        try:
            kind,command,overlays=direct_solc_strategy(source,row)
        except ValueError:
            kind="unresolved"
    version=node_version(row["toolchain"])
    runtime={"PATH":f"/opt/mvscan/node/{version}/bin:/opt/mvscan/yarn/1.22.22/bin:/usr/local/bin:/usr/bin:/bin"}
    if kind=="direct-solc": runtime["MVSCAN_WORKING_DIRECTORY"]="/tmp/analysis-input"
    if "--solc" in command and (source/"foundry.toml").is_file():
        runtime["FOUNDRY_SOLC"]=command[command.index("--solc")+1]
        runtime["FOUNDRY_OFFLINE"]="true"
    return kind,command,overlays,runtime

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dataset"); ap.add_argument("--subject"); ap.add_argument("--kind"); ap.add_argument("--limit",type=int); ap.add_argument("--refresh",action="store_true"); ap.add_argument("--debug-infrastructure",action="store_true"); args=ap.parse_args()
    suffix=(args.kind or "all").replace("-","_").upper()
    status_path=ROOT/"reports"/f"SUBJECT_MANIFEST_DISCOVERY_{suffix}.json"
    rows=list(csv.DictReader(COHORT.open(newline="",encoding="utf-8")))
    if args.dataset: rows=[r for r in rows if r["dataset"]==args.dataset]
    if args.subject: rows=[r for r in rows if r["execution_subject_id"]==args.subject]
    selected=[]
    for row in rows:
        source=(ROOT/row["workspace"]/row["project_root"]).resolve(); kind,command,overlays,runtime=strategy(source,row)
        if args.kind and kind!=args.kind: continue
        selected.append((row,source,kind,command,overlays,runtime))
    if args.limit is not None: selected=selected[:args.limit]
    DEST.mkdir(parents=True,exist_ok=True); records=[]
    env=json.loads((ROOT/"environment/oci_environment_manifest.json").read_text())
    runtime_env=json.loads((ROOT/"environment/environment_manifest.json").read_text())
    compiler_manifest=ROOT/"environment/frozen_svm_compilers.json"
    for index,(row,source,kind,command,overlays,runtime) in enumerate(selected,1):
        identity=f"{row['dataset']}__{row['execution_subject_id']}"; target=DEST/f"{identity}.json"
        if target.exists() and not args.refresh: records.append({"identity":identity,"status":"EXISTS","kind":kind}); continue
        if kind=="unresolved": records.append({"identity":identity,"status":"UNRESOLVED_STRATEGY","kind":kind}); continue
        with tempfile.TemporaryDirectory(prefix="mvscan-manifest-",dir="/tmp") as td:
            base=Path(td); workspace=base/"workspace"; run=base/"run"; run.mkdir()
            subprocess.run(["cp","-a","--reflink=auto",str(source)+"/.",str(workspace)],check=True)
            artifact_digest,_,_=build_artifact_state(workspace)
            if artifact_digest is None:
                records.append({"identity":identity,"status":"MISSING_SCOPED_ARTIFACTS","kind":kind}); continue
            try:
                restored=restore_hardhat_sources(workspace) if kind=="hardhat" else []
            except RuntimeError as error:
                code="MISSING_BUILD_INFO" if "requires frozen build-info" in str(error) else "INVALID_BUILD_INFO"
                records.append({"identity":identity,"status":"SOURCE_RESTORATION_FAILURE","kind":kind,"diagnostic_codes":[code]}); continue
            for rel,value in overlays.items():
                overlay_target=workspace/rel; overlay_target.parent.mkdir(parents=True,exist_ok=True); overlay_target.write_text(value,encoding="utf-8",newline="")
            if kind=="direct-solc":
                restored.extend(restore_standard_json_sources(workspace,next(iter(overlays))))
            if kind=="brownie":
                restored.extend(normalize_brownie_artifact_paths(workspace))
                restored.extend(restore_brownie_sources(workspace))
            attempt=json.loads((ROOT/row["attempt_manifest"]).read_text(encoding="utf-8"))
            original=json.loads((ROOT/attempt["original_files_manifest"]).read_text(encoding="utf-8"))
            project=Path(row["project_root"])
            snapshot_paths=[]
            for value in sorted(original):
                path=Path(value)
                if project != Path("."):
                    try: path=path.relative_to(project)
                    except ValueError: continue
                if (workspace/path).is_file() or (workspace/path).is_symlink(): snapshot_paths.append(path.as_posix())
            for rel in restored:
                if rel not in snapshot_paths: snapshot_paths.append(rel)
            for rel in overlays:
                if rel not in snapshot_paths: snapshot_paths.append(rel)
            snapshot_paths.sort()
            source_digest,files,size=tree_digest(workspace,[workspace/value for value in snapshot_paths])
            shutil.copyfile(ROOT/"runners/container_exec.py",run/"container_exec.py"); (run/"detector").mkdir()
            shutil.copytree(ROOT/"mvscan-smoke/mvscan_plugin",run/"detector/mvscan_plugin")
            shutil.copytree(ROOT/"mvscan-smoke/mvscan_slither_plugin.egg-info",run/"detector/mvscan_slither_plugin.egg-info")
            discovery_command=list(command)
            discovery_command[discovery_command.index("inconsistent_state")]="mvscan_metadata"
            discovery_runtime=prepare_exact_solc_runtime(run,discovery_command,runtime)
            invocation=bwrap_command("",workspace,run,load_named("B0"),0,discovery_command,discovery_runtime)
            try: result=subprocess.run(invocation,cwd=ROOT,text=True,capture_output=True,timeout=1900)
            except subprocess.TimeoutExpired:
                records.append({"identity":identity,"status":"DISCOVERY_TIMEOUT","kind":kind}); continue
            detector=run/"detector.json"
            if not detector.is_file():
                diagnostic_text=(result.stdout or "")+(result.stderr or "")
                for log in (run/"stdout.log",run/"stderr.log"):
                    if log.is_file(): diagnostic_text += log.read_text(encoding="utf-8",errors="replace")
                if args.debug_infrastructure:
                    diagnostic_lines=[]
                    for line in diagnostic_text.splitlines():
                        if re.search(r"(?:Error|Exception|InvalidCompilation|KeyError|AssertionError|Traceback|^\s*File \"/|CRITICAL|WARNING|usage:|unrecognized|not found|failed|No such)",line,re.IGNORECASE):
                            diagnostic_lines.append(line.replace(str(workspace),"<workspace>"))
                    outer_lines=[line.replace(str(workspace),"<workspace>") for line in ((result.stdout or "")+(result.stderr or "")).splitlines()]
                    print(json.dumps({"identity":identity,"infrastructure_diagnostics":diagnostic_lines[-20:],"outer_wrapper_diagnostics":outer_lines[-20:]},sort_keys=True),flush=True)
                patterns={"NETWORK_COMPILER_DOWNLOAD":"binaries.soliditylang.org","MISSING_EXECUTABLE":"No such file or directory","INVALID_COMPILATION":"InvalidCompilation","ASSERTION_ERROR":"AssertionError","SOLC_ERROR":"SolcError","MODULE_NOT_FOUND":"MODULE_NOT_FOUND","PERMISSION_ERROR":"PermissionError"}
                codes=sorted(name for name,value in patterns.items() if value in diagnostic_text)
                records.append({"identity":identity,"status":"DISCOVERY_FAILURE","kind":kind,"exit_code":result.returncode,"diagnostic_codes":codes}); continue
            document=json.loads(detector.read_text(encoding="utf-8"))
            units={u["unit_id"]:u["compilation_metadata"] for u in document.get("compilation_units",[])}
            if not units:
                records.append({"identity":identity,"status":"NO_COMPILATION_UNITS","kind":kind}); continue
            manifest={
              "schema_version":1,"dataset":row["dataset"],"subject_id":row["execution_subject_id"],
              "revision_role":row["revision"],"accepted_build":True,"population_role":"EVALUATION_SUBJECT",
              "source_identity":row["source_identity"],"accepted_attempt_id":row["accepted_attempt_id"],
              "source_path":(Path(row["workspace"])/row["project_root"]).as_posix(),"image_reference":env["image_digest"],
              "analysis_strategy":kind,"analysis_command":command,"runtime_environment":runtime,"workspace_overlays":overlays,
              "restore_hardhat_sources_from_build_info":kind=="hardhat",
              "restore_standard_json_sources_from_overlay":kind=="direct-solc",
              "normalize_brownie_artifact_paths":kind=="brownie",
              "restore_brownie_sources_from_artifacts":kind=="brownie",
              "snapshot_paths":snapshot_paths,
              "expected_inputs":{"source_snapshot_sha256":source_digest,"build_sha256":artifact_digest,
                "accepted_workspace_build_sha256":row["artifact_sha256"],
                "compiler_sha256":sha256_file(compiler_manifest),"environment_digest":runtime_env["immutable_runtime_digest"]},
              "expected_compilation_units":units,"restored_input_file_count":files,"restored_input_byte_size":size,
              "mapped_item_count":int(row["mapped_item_count"])
            }
            target.write_text(json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
            records.append({"identity":identity,"status":"CREATED","kind":kind,"unit_count":len(units)})
        status_path.write_text(json.dumps({"schema_version":1,"records":records},indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"index":index,"total":len(selected),**records[-1]},sort_keys=True),flush=True)
    status_path.write_text(json.dumps({"schema_version":1,"records":records},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"selected":len(selected),"statuses":{s:sum(r["status"]==s for r in records) for s in sorted({r["status"] for r in records})}},sort_keys=True))
if __name__=="__main__": main()
