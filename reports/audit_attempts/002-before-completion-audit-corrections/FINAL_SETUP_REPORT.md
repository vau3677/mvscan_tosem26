# MV-Scan F0/F1 Setup Report

This invocation stopped before every real benchmark MV-Scan run. No benchmark candidate frame, candidate sample, candidate inspection, or accuracy calculation was produced.

## 1. Files created or changed

The complete file-level package inventory is in reports/ARTIFACT_INVENTORY.csv. It lists every regular file and symbolic link currently under benchmarks, configs, detector, deviations, environment, freeze, protocol, runners, schemas, reports, and tests, including acquired repositories and immutable toolchain/rootfs material.

## 2. Detector-hash verification

- inconsistent_state.py: 83999325fe57207d770a02bfb61a0a4389a5d1faeab4a1360d2975aef438c14c (verified)
- icfg.py: 4c26fe2f758da22c1f9710ccd58681e59c687ab2a793fe292d453ca97c0f742b (verified)
- mvscan_env.py: dd9b7bd80f859c91d7820cb2502b7f79027a40938b6a57f4bbee9ea54bcdc176 (verified)

## 3. Protocol-hash verification

- MVSCAN_EVALUATION_PLAN.md: 798f46164e1b3b30496573f094625130b9542f6a7ed11d33a4b30159a54eccf7 (verified)

## 4. Benchmark checkout verification

- SolidityStateStudy: 985e0032449aaa4fec4b6d2f9f7902525cbbb736; clean detached checkout
- Web3Bugs: fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4; clean detached checkout

## 5. Frozen populations

- Historical documented findings: 116 unique rows
- Web3Bugs initial numeric-directory population: 102 unique snapshots

## 6. Build-screen progress and outcomes

- Historical: {"UNAVAILABLE_SOURCE_VERSION": 116}. No vulnerable revision was inferred or synthesized.
- Web3Bugs: {"ENVIRONMENT_UNAVAILABLE": 40, "UNRESOLVED_BUILD_COMMAND": 62}. Forty commands were evidence-resolved but not executed under weakened resource controls; unresolved commands remain explicit.
- No accepted cohort was fabricated. No prohibited source, pragma, lockfile, logic, or checked-in build-configuration edit occurred.

## 7. Environment and toolchains

- Immutable linux/amd64 OCI digest: sha256:3d73bca90bf416127375a3836cfa7272aae89da7d24f6af4071286174b7dd4f6
- Core versions validated in chroot: Python 3.10.20, Slither 0.11.3, crytic-compile 0.3.11, Foundry v1.5.1.
- Toolchain chroot validations: 23; exact solc binaries archived: 19; compiler-unresolved snapshots: 62.
- Official Node profiles archived: 3; JavaScript snapshots mapped: 39; Yarn 1.22.22 archived.
- Runtime enforcement remains blocked: the host lacks newuidmap/newgidmap for rootless Docker and denies moving this session into the delegated cgroup; transient user services exit 219.

## 8. Runner, validator, selector, and tests

- Synthetic-only infrastructure tests: 27 passed.
- Runner is F1-seal guarded and uses unique run IDs/output paths, a clean detector environment, frozen resources, terminal statuses, hashes, raw/canonical preservation, and validation.
- Validator checks F0/configuration/source/build/compiler/environment identities, counts, IDs, relation subsets/complements, witnesses, modeled sinks, and candidate digests.
- Canonicalizer, frozen selectors, and statistics scaffolding are implemented but were not applied to benchmark output.

## 9. Unresolved F1 blockers

- BLOCKED_BUILD_RECONSTRUCTION
- BLOCKED_ENVIRONMENT
- BLOCKED_EXPOSURE_DECLARATION
- BLOCKED_HUMAN_ADJUDICATION
- BLOCKED_HUMAN_ANNOTATION
- BLOCKED_HUMAN_ORACLE

Operational detail: 62 Web3Bugs snapshots still lack an unambiguous permitted command and/or exact compiler selection; 40 resolved commands cannot be accepted until exact runtime resource enforcement is available. All 116 historical rows lack explicit vulnerable repository/revision evidence.

## 10. Exact human actions

Follow protocol/HUMAN_ACTIONS.md. In summary: two annotators independently complete all 116 files rows; an independent adjudicator records exactly the disagreements; the research team supplies one ten-field oracle for every final MV_SI row; and all 218 exposure declarations are reviewed and signed.

## 11. Validate and seal F1

Run only after build/environment and human blockers are resolved:

    python3 -m runners.prepare_f2_plan && python3 -m runners.validate_human_materials && python3 -m runners.check_f1 --seal

## 12. Guarded F2 command

After the preceding command creates a valid seal:

    python3 -m runners.begin_f2 --execute

The F2 launcher rehashes the readiness report and every sealed dependency and refuses stale, absent, or incomplete seals.

## 13. Mandatory stopping condition

- Verified: no F1_SEALED artifact.
- Verified: no nonempty runs directory.
- Verified: both annotation files remain semantically blank.
- Verified: semantic-match oracle file remains empty.
- Verified: no benchmark candidate-generating detector process ran.
