# MV-Scan: TOSEM publication artifact

This artifact contains the evaluated detector, current manuscript, completed annotations, frozen detector outputs, and code to regenerate the six publication tables. The accepted benchmark inputs and pinned Linux runtime are distributed as checksummed data bundles.

Start with [the manuscript](manuscript/main.pdf), [the result tables](results/final/PAPER_TABLES.md), and [the evaluation protocol](protocol/MVSCAN_EVALUATION_PLAN.md). The frozen detector is in [mvscan-smoke/mvscan_plugin](mvscan-smoke/mvscan_plugin/).

## Regenerate the tables

Python 3.10 is sufficient; this step uses committed inputs and does not execute the detector.

```bash
python3.10 publication/restore.py tables
```

The large union inventory is stored losslessly as `freeze/CROSS_ABLATION_UNION_INVENTORY.json.gz`. The bootstrap restores its original bytes and checks SHA-256 before generating tables. Completed Web3Bugs review, both ISU reviews, final adjudication, and strict-match decisions remain under `human_review/` and `benchmarks/isu/`.

The five samples contain 2,000 selections, 1,270 distinct reviewed buckets, and 376 buckets selected by multiple configurations. The original frozen sample's summary field says 156; the generator now derives overlap from the unchanged selection lists. See [the preparation record](publication/PREPARATION.md). Precision, labels, recovery counts, and detector outputs are unchanged.

## Restore the evaluated inputs and runtime

Detector execution requires Linux/amd64 with Bubblewrap, GNU coreutils, and the resources declared in `environment/resource_manifest.json`. Allow approximately 20 GB of free disk space for a full restored workspace.

```bash
python3.10 publication/restore.py inputs --download
python3.10 publication/restore.py runtime --download
python3.10 publication/restore.py verify
python3.10 -m unittest discover -s tests -q
python3.10 publication/check_detector_regressions.py
```

[The bundle manifest](publication/artifact-bundles.json) lists each asset's size and SHA-256. Downloaded bundles live in ignored `publication/data/`; extracted workspaces and runtime files are also ignored. Repository internals, repeated dependency installations, failed build workspaces, and housekeeping archives are excluded from the publication distribution.

The selected input files reconstruct **all 153 evaluated subjects with exactly their frozen source-snapshot and compiler-artifact hashes**. [The subject-by-subject validation](benchmarks/bundles/restoration-validation.json) records the checks. Source evidence includes all 6,454 scope-declared Web3Bugs source files, the historical oracle corpus, ISU Solidity originals, and revision-resolution evidence.

## Run MV-Scan

Use one subject manifest and one frozen configuration:

```bash
python3.10 -m runners.run_mvscan \
  benchmarks/subject_manifests/isu__<execution_subject_id>.json \
  --configuration B0 --seed 0 --repetition 1 --execute
```

Configurations are `B0`, `A1`, `A2`, `A4`, and `A5`. Eight ISU subjects require the accepted Slither compatibility-recovery runner:

```bash
python3.10 -m runners.run_mvscan_recovery \
  benchmarks/subject_manifests/isu__<execution_subject_id>.json \
  --configuration B0 --seed 0 --repetition 1 --execute
```

The eight subject IDs are `3b40d4c2e2c5c78d66a1`, `45244eb6ad77ecbb8d10`, `57417c735ac666efab33`, `7243363cfd2599257952`, `8d760c6fa69de52797f1`, `b6da317163e7b77bd40c`, `bee019e8a0d6149543c5`, and `fed6883739d838ef60fe`. The accepted recovery attempts and compatibility changes are documented in `benchmarks/isu/analysis_failure_recovery.csv` and `environment/recovery_patches/`.

Both runners create new attempt directories. The published manifests and outputs preserve the original attempts used for the results. Redundant run-local code/compiler copies, empty logs, lock files, and unused template extras are ignored rather than deleted from the local workspace. Their original bytes remain in Git commit `3e9b63c37a4558a2e31560593ce768d9c5d1a867`; the compressed integrity inventory is `publication/ignored-material.json.gz`. To restore all historical paths for an integrity audit, run:

```bash
python3.10 publication/restore.py historical --download
```

This checks every original file or symlink, restores missing paths, and refuses to overwrite locally changed files. The option fetches the preserved commit only if it is missing from the clone. Table regeneration and new detector execution do not require these historical copies.

## Evidence and preservation

- `runs/`: 954 terminal attempt manifests and original detector outputs, including failures and accepted recovery attempts.
- `freeze/`: original selections, determinism report, inventory, and historical evaluation snapshot.
- `human_review/`: completed reviews and supporting human-review materials.
- `benchmarks/`: populations, scope, acquisition/build decisions, adjudications, and subject manifests.
- `manuscript/`: the current local manuscript and pinned ACM template.
- `validation/backd/`: two locally authored regression tests preserved during reconciliation.
- `publication/VALIDATION.json`: preservation checks and explicit historical snapshot differences.

The three evaluated detector modules retain their original frozen hashes. The historical evaluation snapshot has 185 matching artifacts and nine later review/protocol/interface changes that were already present on the remote before this copy. These differences are listed explicitly; the historical snapshot itself remains unchanged.

Upstream development configurations are preserved where required by the frozen snapshot hashes. [Public fixture provenance](publication/UPSTREAM_FIXTURE_PROVENANCE.json) records the original source URLs and byte-level checks without repeating credential-like fixture values.
