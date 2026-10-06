from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import runners.configuration as configuration_module
import runners.container_exec as container_exec_module
from runners.artifact_storage import compress_verified, read_json
from runners.build_candidate_union import global_candidate_id, resolve_source_scope, structural_payload
from runners.canonicalize_json import canonicalize
from runners.common import ROOT, build_artifact_state, restore_hardhat_sources, restore_standard_json_sources, sha256_file, tree_digest
from runners.configuration import (
    CONFIG_NAMES,
    detector_effective_config,
    load_named,
    parse_env,
)
from runners.prepare_subject_manifests import direct_solc_strategy, foundry_artifact_standard_json_strategy, strategy
from runners.run_mvscan import (
    apply_semantic_embargo,
    build_run_id,
    bwrap_command,
    docker_command,
    prepare_exact_solc_runtime,
    snapshot_digest,
    terminal_status,
    write_failure_manifest,
)
from runners.select_samples import (
    AGREEMENT_DOMAIN,
    PRIMARY_DOMAIN,
    digest,
    select_agreement,
    select_primary,
    select_configurations,
)
from runners.statistics import agreement, finite_population_95, historical_counts, primary_precision, wilson_95
from runners.validate_output import (
    EXPECTED_DETECTOR_HASHES,
    ValidationError,
    structural_digest,
    validate_document,
    validate_run,
)

def synthetic_document():
    config = detector_effective_config(load_named("B0"))
    candidate = {
        "candidate_id": "candidate-1",
        "writer_owner": "C.f()",
        "writer_block": {"function_key": "C.f()", "node_id": 1, "file": "Fixture.sol", "line": 1},
        "relation": {
            "members": [
                {"name": "a", "entity_key": ["C", "a"]},
                {"name": "b", "entity_key": ["C", "b"]},
            ]
        },
        "supporting_origin_sites": [],
        "written_members": [["C", "a"]],
        "potentially_stale_members": [["C", "b"]],
        "context_instance_count": 1,
        "reader_witness_count": 1,
        "context_instances": [
            {
                "writer_owner": "C.f()",
                "writer_storage_context": "C",
                "writer_active_sender": "sender",
                "reader_owner": "C.g()",
                "reader_storage_context": "C",
                "reader_active_sender": "sender",
                "writer_bid": ["C.f()", 1],
                "reader_bid": ["C.g()", 2],
            }
        ],
        "reader_witnesses": [
            {
                "subject_index": 0,
                "writer_reaches_reader": True,
                "reader_reaches_writer": False,
                "writer": {},
                "reader": {},
                "relation_evidence": [
                    {
                        "writer_location": {"entity_key": ["C", "a"]},
                        "writer_member": {"entity_key": ["C", "a"]},
                        "reader_location": {"entity_key": ["C", "b"]},
                        "reader_member": {"entity_key": ["C", "b"]},
                        "key_constraints": [],
                    }
                ],
                "sinks": [
                    {
                        "function_key": "C.g()",
                        "node_id": 2,
                        "ir_index": 0,
                        "kind": "control",
                    }
                ],
            }
        ],
        "sink_sites": [],
        "call_paths": [],
        "key_equality_constraints": [],
    }
    candidates = [candidate]
    stats = {
        "candidate_count": 1,
        "context_instance_count": 1,
        "reader_witness_count": 1,
        "candidate_digest": structural_digest(candidates),
    }
    compilation = {
        "solidity_compiler_version": "0.8.20",
        "target_source_digest": "1" * 64,
        "build_info_digest": "2" * 64,
    }
    document = {
        "detector": {
            "name": "MV-Scan",
            "python_version": "3.10.20",
            "slither_version": "0.11.3",
            "source_hashes": dict(EXPECTED_DETECTOR_HASHES),
        },
        "effective_config": copy.deepcopy(config),
        "candidate_count": 1,
        "context_instance_count": 1,
        "reader_witness_count": 1,
        "compilation_units": [
            {
                "unit_id": "unit-1",
                "compilation_metadata": compilation,
                "stats": stats,
                "relations": [],
                "calls": [],
                "candidates": candidates,
                "candidate_count": 1,
                "context_instance_count": 1,
                "reader_witness_count": 1,
            }
        ],
    }
    return document, config, {"unit-1": compilation}



class HardhatArtifactTests(unittest.TestCase):
    def test_build_info_restores_missing_sources_and_has_a_frozen_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            build_info = workspace / "artifacts" / "build-info" / "fixture.json"
            build_info.parent.mkdir(parents=True)
            content = "pragma solidity 0.8.17; contract Dependency {}"
            document = {"input": {"sources": {"node_modules/pkg/Dependency.sol": {"content": content}}}}
            build_info.write_text(json.dumps(document), encoding="utf-8")
            restored = restore_hardhat_sources(workspace)
            self.assertEqual(restored, ["node_modules/pkg/Dependency.sol"])
            self.assertEqual((workspace / restored[0]).read_text(encoding="utf-8"), content)
            artifact_digest, files, byte_size = build_artifact_state(workspace)
            self.assertIsNotNone(artifact_digest)
            self.assertEqual(files, 1)
            self.assertGreater(byte_size, 0)
            self.assertEqual(restore_hardhat_sources(workspace), [])


    def test_strategy_freezes_nondefault_hardhat_artifact_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "hardhat.config.ts").write_text("export default {}", encoding="utf-8")
            (source / "artifacts-zk" / "build-info").mkdir(parents=True)
            row = {"build_command": "npx hardhat compile", "toolchain": "node16-npm8"}
            kind, command, _, _ = strategy(source, row)
            self.assertEqual(kind, "hardhat")
            self.assertIn("artifacts-zk", command)


class DirectSolcManifestTests(unittest.TestCase):
    def test_modern_foundry_artifacts_reconstruct_standard_json(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (source / "src").mkdir()
            (source / "src/F.sol").write_text("contract F {}\n", encoding="utf-8")
            (source / "out/build-info").mkdir(parents=True)
            (source / "out/build-info/unit.json").write_text(
                json.dumps({"source_id_to_path": {"0": "src/F.sol"}}), encoding="utf-8"
            )
            (source / "out/F.sol").mkdir()
            metadata = {
                "compiler": {"version": "0.8.17+commit.8df45f5f"},
                "settings": {"compilationTarget": {"src/F.sol": "F"}, "optimizer": {"enabled": True, "runs": 200}},
            }
            (source / "out/F.sol/F.json").write_text(
                json.dumps({"rawMetadata": json.dumps(metadata)}), encoding="utf-8"
            )
            kind, command, overlays = foundry_artifact_standard_json_strategy(
                source, {"execution_subject_id": "fixture"}
            )
            self.assertEqual(kind, "direct-solc")
            self.assertIn("/tmp/.svm/0.8.17/solc-0.8.17", command)
            document = json.loads(overlays[".mvscan-input/mvscan-standard-input.json"])
            self.assertEqual(document["sources"]["src/F.sol"]["content"], "contract F {}\n")
            self.assertNotIn("compilationTarget", document["settings"])

    def test_standard_json_inline_sources_are_restored_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "mvscan-standard-input.json").write_text(
                json.dumps({"sources": {"vendor/Dependency.sol": {"content": "contract Dependency {}\n"}}}),
                encoding="utf-8",
            )
            self.assertEqual(
                restore_standard_json_sources(workspace),
                ["vendor/Dependency.sol"],
            )
            self.assertEqual(
                (workspace / "vendor/Dependency.sol").read_text(encoding="utf-8"),
                "contract Dependency {}\n",
            )
            self.assertEqual(restore_standard_json_sources(workspace), [])

    def test_existing_standard_input_is_frozen_as_workspace_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            generated = source / "build" / "direct-solc"
            generated.mkdir(parents=True)
            document = {
                "language": "Solidity",
                "sources": {"Fixture.sol": {"content": "pragma solidity 0.8.17; contract Fixture {}"}},
                "settings": {"outputSelection": {"*": {"": ["ast"]}}},
            }
            (generated / "standard-input.json").write_text(json.dumps(document), encoding="utf-8")
            row = {
                "execution_subject_id": "fixture",
                "build_command": "python runners/direct_solc_build.py --version 0.8.17",
            }
            kind, command, overlays = direct_solc_strategy(source, row)
            self.assertEqual(kind, "direct-solc")
            self.assertEqual(list(overlays), [".mvscan-input/mvscan-standard-input.json"])
            self.assertEqual(json.loads(next(iter(overlays.values()))), document)
            self.assertIn("solc-json", command)
            self.assertIn("/tmp/.svm/0.8.17/solc-0.8.17", command)

    def test_direct_solc_requires_a_frozen_version(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "version unavailable"):
                direct_solc_strategy(
                    Path(directory),
                    {"execution_subject_id": "fixture", "build_command": "solc Fixture.sol"},
                )


class ConfigurationTests(unittest.TestCase):
    def test_wrapper_working_directory_is_not_detector_visible(self):
        with mock.patch.dict(
            container_exec_module.os.environ,
            {"MVSCAN_WORKING_DIRECTORY": "/tmp/analysis-input", "PYTHONHASHSEED": "0"},
            clear=True,
        ):
            environment = container_exec_module.sanitized_child_environment()
        self.assertNotIn("MVSCAN_WORKING_DIRECTORY", environment)
        self.assertEqual(environment["PYTHONHASHSEED"], "0")

    def test_all_frozen_configurations_parse(self):
        values = {name: load_named(name) for name in CONFIG_NAMES}
        self.assertEqual(values["A1"]["MVSCAN_ABLATION"], "no_branch_groups")
        self.assertEqual(values["A2"]["MVSCAN_ABLATION"], "no_multi_return_groups")
        self.assertEqual(values["A4"]["MVSCAN_ABLATION"], "mapping_insensitive")
        self.assertEqual(values["A5"]["MVSCAN_CONTEXTUAL_KEYS"], "0")
        a4_effective = detector_effective_config(values["A4"])
        self.assertEqual(a4_effective["MAPPING_MODE"], "base_collapsed")
        self.assertFalse(a4_effective["REQUIRE_SAME_SLOT_KEY"])

    def test_type_valid_but_unfrozen_value_rejected(self):
        rows = (ROOT / "configs" / "B0.env").read_text(
            encoding="utf-8"
        ).splitlines()
        altered = [
            "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK=129"
            if row.startswith("MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK=")
            else row
            for row in rows
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "configs").mkdir()
            (root / "configs" / "B0.env").write_text(
                "\n".join(altered) + "\n", encoding="utf-8"
            )
            with (
                mock.patch.object(configuration_module, "ROOT", root),
                self.assertRaisesRegex(ValueError, "frozen configuration"),
            ):
                configuration_module.load_named("B0")

    def malformed(self, transform):
        rows = (ROOT / "configs" / "B0.env").read_text(encoding="utf-8").splitlines()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.env"
            path.write_text("\n".join(transform(rows)) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_env(path)

    def test_malformed_boolean_rejected(self):
        self.malformed(lambda rows: ["MVSCAN_CONTEXTUAL_KEYS=true" if row.startswith("MVSCAN_CONTEXTUAL_KEYS=") else row for row in rows])

    def test_malformed_enumeration_rejected(self):
        self.malformed(lambda rows: ["MVSCAN_ABLATION=unknown" if row.startswith("MVSCAN_ABLATION=") else row for row in rows])

    def test_unknown_mvscan_rejected(self):
        self.malformed(lambda rows: [*rows, "MVSCAN_SURPRISE=1"])



class RunnerFailureTests(unittest.TestCase):
    def test_terminal_statuses_are_mutually_exclusive(self):
        cases = (
            ((0, False, "", False), ("SUCCESS", False)),
            ((1, False, "exception", False), ("ANALYSIS_FAILURE", False)),
            ((0, True, "", False), ("ANALYSIS_TIMEOUT", False)),
            ((-9, False, "", True), ("OOM", False)),
            ((75, False, "", False), ("OTHER_FAILURE", False)),
            ((1, False, "max contexts reached", False), ("CONTEXT_BOUND_FAILURE", True)),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected[0]):
                self.assertEqual(terminal_status(*arguments), expected)

    def test_container_command_enforces_frozen_allocation(self):
        command = docker_command(
            "mvscan@sha256:fixture",
            Path("/tmp/mvscan-fixture-workspace"),
            Path("/tmp/mvscan-fixture-run"),
            load_named("B0"),
            0,
            ["slither", "."],
        )
        self.assertEqual(
            command[:5],
            [
                "flock",
                "--exclusive",
                "--nonblock",
                "--conflict-exit-code",
                "75",
            ],
        )
        self.assertTrue(command[5].endswith("/runs/.analysis.lock"))
        self.assertEqual(command[6:8], ["docker", "run"])
        for option, expected in (
            ("--network", "none"),
            ("--cpus", "4"),
            ("--memory", "34359738368"),
            ("--memory-swap", "34359738368"),
            ("--workdir", "/workspace"),
        ):
            index = command.index(option)
            self.assertEqual(command[index + 1], expected)
        self.assertIn("PYTHONHASHSEED=0", command)
        self.assertIn("ISD_JSON_OUT=/mnt/detector.json", command)

    def test_bwrap_command_enforces_frozen_allocation(self):
        command = bwrap_command(
            "ignored@sha256:fixture",
            Path("/tmp/mvscan-fixture-workspace"),
            Path("/tmp/mvscan-fixture-run"),
            load_named("B0"),
            0,
            ["slither", "."],
        )
        self.assertEqual(command[:5], ["flock", "--exclusive", "--nonblock", "--conflict-exit-code", "75"])
        self.assertIn("prlimit", command)
        self.assertIn("--as=34359738368", command)
        self.assertIn("taskset", command)
        self.assertIn("bwrap", command)
        self.assertIn("--unshare-net", command)
        self.assertIn(str(ROOT / "environment" / "oci-rootfs"), command)
        self.assertIn("/workspace", command)
        self.assertIn("/mnt", command)
        self.assertIn("PYTHONHASHSEED=0", command)
        self.assertIn("ISD_JSON_OUT=/mnt/detector.json", command)
        self.assertIn("PYTHONPATH=/mnt/detector", command)

    def test_semantic_embargo_removes_all_access_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            for name in ("detector.json", "detector.canonical.json", "stdout.log", "stderr.log"):
                (run / name).write_text("embargoed", encoding="utf-8")
            record = apply_semantic_embargo(run)
            self.assertTrue(record["applied"])
            self.assertEqual(set(record["protected_files"]), {"detector.json", "detector.canonical.json", "stdout.log", "stderr.log"})
            self.assertTrue(all((run / name).stat().st_mode & 0o777 == 0 for name in record["protected_files"]))

    def test_snapshot_digest_is_scoped_and_detects_selected_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.sol").write_text("pragma solidity 0.8.20;\n", encoding="utf-8")
            (root / "generated.json").write_text("one", encoding="utf-8")
            before = snapshot_digest(root, ["source.sol"])
            (root / "generated.json").write_text("two", encoding="utf-8")
            self.assertEqual(snapshot_digest(root, ["source.sol"]), before)
            (root / "source.sol").write_text("pragma solidity 0.8.21;\n", encoding="utf-8")
            self.assertNotEqual(snapshot_digest(root, ["source.sol"]), before)

    def test_bwrap_runtime_path_override_is_narrowly_validated(self):
        command = bwrap_command(
            "ignored", Path("/tmp/work"), Path("/tmp/run"), load_named("B0"), 0,
            ["slither", "."], {"PATH": "/opt/mvscan/node/18.20.8/bin:/usr/local/bin:/usr/bin:/bin"},
        )
        self.assertIn("PATH=/opt/mvscan/node/18.20.8/bin:/usr/local/bin:/usr/bin:/bin", command)
        self.assertIn("/tmp/.svm", command)
        with self.assertRaisesRegex(ValueError, "unsupported runtime environment override"):
            bwrap_command("", Path("/tmp/work"), Path("/tmp/run"), load_named("B0"), 0, ["true"], {"HOME": "/unsafe"})

        foundry = bwrap_command(
            "", Path("/tmp/work"), Path("/tmp/run"), load_named("B0"), 0, ["true"],
            {"FOUNDRY_OFFLINE": "true", "FOUNDRY_SOLC": "/tmp/.svm/0.8.17/solc-0.8.17"},
        )
        self.assertIn("FOUNDRY_OFFLINE=true", foundry)
        self.assertIn("FOUNDRY_SOLC=/tmp/.svm/0.8.17/solc-0.8.17", foundry)

    def test_exact_solc_runtime_pins_bare_standard_json_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            runtime = prepare_exact_solc_runtime(
                run,
                ["slither", "input.json", "--solc", "/tmp/.svm/0.8.9/solc-0.8.9"],
                {"PATH": "/usr/local/bin:/usr/bin:/bin"},
            )
            shim = run / "compiler-bin" / "solc"
            self.assertTrue(shim.is_symlink())
            self.assertEqual(shim.readlink().as_posix(), "/tmp/.svm/0.8.9/solc-0.8.9")
            self.assertEqual(
                runtime["PATH"],
                "/mnt/compiler-bin:/usr/local/bin:/usr/bin:/bin",
            )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "inside the frozen SVM mount"):
                prepare_exact_solc_runtime(
                    Path(directory), ["slither", "input.json", "--solc", "/usr/bin/solc"], {}
                )

    def test_outer_failure_writes_one_terminal_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            workspace = run / "workspace"
            workspace.mkdir(parents=True)
            (workspace / "Fixture.sol").write_text(
                "pragma solidity 0.8.20;\n", encoding="utf-8"
            )
            pending = {
                "schema_version": 1,
                "expected_inputs": {
                    "source_snapshot_sha256": "expected",
                    "build_sha256": "build",
                    "compiler_sha256": "compiler",
                    "environment_digest": "environment",
                },
            }
            (run / "run_manifest.pending.json").write_text(
                json.dumps(pending), encoding="utf-8"
            )
            (run / "container_exec.py").write_text(
                "# synthetic wrapper\n", encoding="utf-8"
            )
            write_failure_manifest(
                pending,
                run,
                workspace,
                time.time(),
                "OTHER_FAILURE",
                RuntimeError("synthetic outer failure"),
            )
            manifest = json.loads(
                (run / "run_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["terminal_status"], "OTHER_FAILURE")
            self.assertEqual(manifest["failure_type"], "RuntimeError")
            self.assertEqual(manifest["canonical_json_sha256"], None)


class CanonicalizationTests(unittest.TestCase):
    def test_idempotent_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            first = root / "first.json"
            second = root / "second.json"
            source.write_text('{ "z": 1, "a": [3, {"y": 2, "x": 1}] }\n', encoding="utf-8")
            digest_1 = canonicalize(source, first)
            digest_2 = canonicalize(first, second)
            expected = b'{"a":[3,{"x":1,"y":2}],"z":1}\n'
            self.assertEqual(first.read_bytes(), expected)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(digest_1, digest_2)
            self.assertEqual(digest_1, hashlib.sha256(expected).hexdigest())

    def test_verified_compression_roundtrip_and_json_read(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "detector.json"
            payload = b'{"a":[1,2,3],"z":"evidence"}\n'
            source.write_bytes(payload)
            record = compress_verified(
                source, expected_sha256=hashlib.sha256(payload).hexdigest()
            )
            compressed = Path(directory) / str(record["path"])
            self.assertFalse(source.exists())
            self.assertTrue(compressed.is_file())
            self.assertTrue(record["roundtrip_verified"])
            self.assertEqual(read_json(compressed), {"a": [1, 2, 3], "z": "evidence"})


class IdentifierAndSelectionTests(unittest.TestCase):
    def test_cross_configuration_selection_deduplicates_review_work(self):
        result = select_configurations({
            "A1": ["shared", "a1-only"],
            "B0": ["shared", "b0-only"],
        })
        self.assertEqual(set(result["unique_primary"]), {"shared", "a1-only", "b0-only"})
        self.assertEqual(result["by_configuration"]["A1"], ["a1-only", "shared"])
        self.assertEqual(result["by_configuration"]["B0"], ["b0-only", "shared"])

    def test_structural_identity_preserves_material_witness_detail(self):
        manifest = {"dataset": "isu", "subject": "s", "revision_role": "vulnerable"}
        candidate = {
            "writer_owner": "C.entry()",
            "writer_block": {"function_key": "C.f()", "node_id": 7, "file": "C.sol", "line": 12},
            "relation": {"members": [
                {"entity_key": ["SV", "C.sol", "C.a"], "kind": "state"},
                {"entity_key": ["SV", "C.sol", "C.b"], "kind": "state"},
            ]},
            "written_members": [["SV", "C.sol", "C.a"]],
            "potentially_stale_members": [["SV", "C.sol", "C.b"]],
            "key_equality_constraints": [],
        }
        origins = [{"function_key": "C.sol::C::rel()", "block_id": 1, "expression": "a == b"}]
        witnesses = [{"reader": {"file": "C.sol", "line": 20, "signature": "C.read()", "block": 3,
                         "context": {"owner": "C.consume()", "storage_context": "C"}},
                      "writer": {"context": {"owner": "C.entry()"}},
                      "sinks": [{"function_key": "C.sol::C::read()", "node_id": 9, "kind": "control"}],
                      "relation_evidence": ["origin:1"]}]
        first = global_candidate_id(structural_payload(manifest, candidate, origins, witnesses))
        changed = copy.deepcopy(candidate)
        changed["writer_block"]["line"] = 999
        second = global_candidate_id(structural_payload(manifest, changed, origins, witnesses))
        self.assertEqual(first, second)
        changed_witnesses = copy.deepcopy(witnesses)
        changed_witnesses[0]["sinks"][0]["node_id"] = 10
        self.assertNotEqual(first, global_candidate_id(structural_payload(manifest, changed, origins, changed_witnesses)))
        changed["potentially_stale_members"] = [["SV", "C.sol", "C.a"]]
        self.assertNotEqual(first, global_candidate_id(structural_payload(manifest, changed, origins, witnesses)))

    def test_source_scope_resolves_compiler_roots_and_dependencies(self):
        source_scope = {
            ("22", "contracts/contracts/LongShort.sol"): "IN_SCOPE",
            ("22", "contracts/test/Harness.sol"): "OUT_OF_SCOPE",
        }
        self.assertEqual(
            resolve_source_scope("22", "contracts/LongShort.sol", source_scope),
            "IN_SCOPE",
        )
        self.assertEqual(
            resolve_source_scope("22", "contracts/test/Harness.sol", source_scope),
            "OUT_OF_SCOPE",
        )
        self.assertEqual(resolve_source_scope("22", "src/PriceMock.sol", source_scope), "OUT_OF_SCOPE")
        self.assertEqual(resolve_source_scope("22", "lib/Dependency.sol", source_scope), "OUT_OF_SCOPE")
        self.assertEqual(
            resolve_source_scope("22", "@openzeppelin/contracts/Ownable.sol", source_scope),
            "OUT_OF_SCOPE",
        )
        self.assertEqual(
            resolve_source_scope("22", "contracts/NewFirstParty.sol", source_scope),
            "IN_SCOPE",
        )
        self.assertEqual(resolve_source_scope("22", None, source_scope), "MISSING")

    def test_every_run_id_field_changes_identity(self):
        base = ("web3bugs", "3", "vulnerable", "B0", 0, 1)
        ids = {build_run_id(*base)}
        for index, replacement in enumerate(("isu", "4", "fixed", "A1", 1, 2)):
            changed = list(base)
            changed[index] = replacement
            ids.add(build_run_id(*changed))
        self.assertEqual(len(ids), 7)

    def test_selector_domains_and_determinism(self):
        ids = [f"candidate-{index:04d}" for index in range(500)]
        expected_primary = [value for _, value in sorted((hashlib.sha256(PRIMARY_DOMAIN.encode("utf-8") + value.encode("utf-8")).hexdigest(), value) for value in ids)[:400]]
        self.assertEqual(select_primary(ids), expected_primary)
        self.assertEqual(select_primary(reversed(ids)), expected_primary)
        expected_agreement = [value for _, value in sorted((hashlib.sha256(AGREEMENT_DOMAIN.encode("utf-8") + value.encode("utf-8")).hexdigest(), value) for value in expected_primary)[:200]]
        self.assertEqual(select_agreement(expected_primary), expected_agreement)
        self.assertEqual(digest(PRIMARY_DOMAIN, ids[0]), hashlib.sha256(b"20260811candidate-0000").hexdigest())

    def test_small_primary_selects_all_deterministically(self):
        self.assertEqual(select_primary(["z", "a"]), ["a", "z"])


class ValidatorTests(unittest.TestCase):
    def test_valid_synthetic_document(self):
        document, config, expected = synthetic_document()
        summary = validate_document(document, config, expected)
        self.assertEqual(summary["candidate_count"], 1)

    def assert_invalid(self, mutate):
        document, config, expected = synthetic_document()
        mutate(document)
        with self.assertRaises(ValidationError):
            validate_document(document, config, expected)

    def test_detector_hash_rejected(self):
        self.assert_invalid(lambda d: d["detector"]["source_hashes"].update({"icfg": "bad"}))

    def test_effective_config_rejected(self):
        self.assert_invalid(lambda d: d["effective_config"].update({"MVSCAN_CONTEXTUAL_KEYS": False}))

    def test_relation_arity_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0]["relation"].update({"members": [{"entity_key": ["C", "a"]}]}))

    def test_empty_written_members_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0].update({"written_members": []}))

    def test_incorrect_relation_complement_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0].update({"potentially_stale_members": [["C", "a"]]}))

    def test_missing_witness_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0].update({"reader_witnesses": [], "reader_witness_count": 0}))

    def test_witness_member_direction_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0]["reader_witnesses"][0]["relation_evidence"][0]["reader_member"].update({"entity_key": ["C", "a"]}))

    def test_unsupported_sink_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["candidates"][0]["reader_witnesses"][0]["sinks"][0].update({"kind": "logging"}))

    def test_aggregate_count_rejected(self):
        self.assert_invalid(lambda d: d.update({"candidate_count": 2}))

    def test_candidate_digest_rejected(self):
        self.assert_invalid(lambda d: d["compilation_units"][0]["stats"].update({"candidate_digest": "0" * 64}))

    def test_duplicate_candidate_id_rejected(self):
        def mutate(document):
            unit = document["compilation_units"][0]
            duplicate = copy.deepcopy(unit["candidates"][0])
            unit["candidates"].append(duplicate)
            unit["candidate_count"] = 2
            unit["stats"]["candidate_count"] = 2
            unit["stats"]["candidate_digest"] = structural_digest(unit["candidates"])
            document["candidate_count"] = 2
        self.assert_invalid(mutate)


    def test_in_memory_manifest_validation(self):
        document, _, expected = synthetic_document()
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "detector.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            values = {
                "source_snapshot_sha256": "a",
                "build_sha256": "b",
                "compiler_sha256": "c",
                "environment_digest": "d",
            }
            manifest = {
                "terminal_status": "SUCCESS",
                "process_exit_code": 0,
                "timed_out": False,
                "oom_killed": False,
                "context_bound_failure": False,
                "expected_inputs": values,
                "actual_inputs": values,
                "detector_json": "detector.json",
                "configuration": "B0",
                "expected_compilation_units": expected,
            }
            summary = validate_run(run, manifest=manifest)
            self.assertEqual(summary["candidate_count"], 1)

    def test_partial_output_rejected(self):
        document, config, expected = synthetic_document()
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "detector.json").write_text(json.dumps(document), encoding="utf-8")
            (run / "detector.json.tmp.1").write_text("partial", encoding="utf-8")
            values = {"source_snapshot_sha256": "a", "build_sha256": "b", "compiler_sha256": "c", "environment_digest": "d"}
            manifest = {
                "terminal_status": "SUCCESS",
                "process_exit_code": 0,
                "timed_out": False,
                "oom_killed": False,
                "context_bound_failure": False,
                "expected_inputs": values,
                "actual_inputs": values,
                "detector_json": "detector.json",
                "configuration": "B0",
                "expected_compilation_units": expected,
            }
            (run / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValidationError):
                validate_run(run)


class FreezeAndSourceTests(unittest.TestCase):
    def test_frozen_hashes(self):
        detector_root = ROOT / "mvscan-smoke" / "mvscan_plugin"
        paths = {
            "inconsistent_state": detector_root / "inconsistent_state.py",
            "icfg": detector_root / "utils" / "icfg.py",
            "mvscan_env": detector_root / "utils" / "mvscan_env.py",
        }
        self.assertEqual({name: sha256_file(path) for name, path in paths.items()}, EXPECTED_DETECTOR_HASHES)

    def test_source_hash_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.sol").write_text("pragma solidity 0.8.20;\n", encoding="utf-8")
            before = tree_digest(root)
            _ = (root / "A.sol").read_bytes()
            after = tree_digest(root)
            self.assertEqual(before, after)

class StatisticsTests(unittest.TestCase):
    def test_frozen_statistics(self):
        precision = primary_precision(["TP_MVSI", "NONBUG", "TP_MVSI"])
        self.assertEqual(precision["tp_mvsi"], 2)
        self.assertEqual(precision["audited_structural_buckets"], 3)
        self.assertEqual(finite_population_95(2, 3, 3), (2 / 3, 2 / 3))
        self.assertEqual(wilson_95(0, 0), (None, None))
        result = agreement(["a", "b"], ["a", "a"])
        self.assertEqual(result["n"], 2)
        counts = historical_counts([
            {"adjudicated_class": "MV_SI", "accepted_build": True, "semantic_match": True},
            {"adjudicated_class": "MV_SI", "accepted_build": False, "semantic_match": False},
        ])
        self.assertEqual((counts["H"], counts["B"], counts["M"]), (2, 1, 1))


if __name__ == "__main__":
    unittest.main()
