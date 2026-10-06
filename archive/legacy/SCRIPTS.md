# SCRIPTS.md - Script Reference

This document describes scripts in this repository: what they do, how they work internally, how to run them, and what they output.
<!-- 
---

## Table of Contents

**Important files:**

- `dataset/results.tsv`: this TSV holds all ablation results for replication

**Important scripts:**

- [dataset/main.py](#datasetmainpy)
- [inconsistent_state (our Slither detector)](#inconsistent_state-slither-detector)
- [dataset/info.py](#datasetinfopy)
- [dataset/fails.py](#datasetfailspy)
- [dataset/tools/remove_failed_detections.py](#datasettoolsremovefaileddetectionspy)
- [dataset/tests_left.py](#datasettestsleftpy)
- [evaluation/master.py](#evaluationmasterpy)

---

## dataset/main.py

**Purpose:** Runs MV-Scan ablation study across a dataset of Solidity projects. It discovers contract project roots, infers the framework for each project, executes the detector once per ablation configuration, captures runtime/output artifacts, and records resumable TSV results alongside an `out/` dir with results.

**How it works:**

1. Resolves the dataset root from `--dataset-dir` and the contract subtree from `--contracts-subdir`.
2. Recursively scans for candidate project roots using `find_config_dirs()`. Keeps only directories containing a recognized framework config and respects the `SKIP_DIRS` filter.
3. Loads ablations and writes a stable ablation index.
4. Skips any project for which all requested ablations are already recorded.
5. For each project, infers the framework with `detect_framework()` with a fallback to `contracts/**/*.sol` or `src/**/*.sol`.
6. Starts from ```slither . --detect inconsistent_state```, appends framework-specific “ignore compile” and “force framework” flags (useful for debugging failed test runs).
7. For each ablation: injects the ablation env variables, sets `ISD_JSON_OUT` to the per-run JSON path, runs the command with timeout protection, captures stdout/stderr together, extracts the analyzer tail summary if present, and records elapsed runtime and return code.
8. For each project/ablation, writes `out/<label>/<ablation_id>/findings.json`, `out/<label>/<ablation_id>/slither_stdout.txt`, and `out/<label>/<ablation_id>/meta.json`.
9. Appends one summary line to the results TSV, namely:
```text
<label>    <ablation_name>    <status_line>    <elapsed_sec>    <rc>
```

**Usage:**

Basic usage (will work, but may fail on specific repos if automated compilation fails):

```bash
python3 main.py --dataset-dir ./Web3Bugs --contracts-subdir contracts
```

To isolate a failed test, first delete it from your `results.tsv` and run:

```bash
python3 main.py --only <repo> <env flags>
```

**Arguments:**
- `--dataset-dir`: dataset root (default: `./Web3Bugs`)
- `--contracts-subdir`: contract subtree under the dataset root (default: `contracts`)
- `--out-json`: declared JSON output name, though the current implementation writes fixed per-run `findings.json` paths
- `--cmd`: base detector command (default: `slither . --detect inconsistent_state`)
- `--timeout-run`: per-run timeout in seconds (default: `600`)
- `--only`: optional substring filter for project labels
- `--results-file`: resumable TSV output path (default: `out/done.tsv`)
- `--abl`: repeatable inline ablation specification
- `--abl-file`: JSON file containing ablation definitions

**Inputs:**
- A dataset directory containing Solidity project roots under the configured contracts subtree.
- A Python 3.10+ environment with `slither-si-detector` installed by running `python3.10 -m pip install -e slither-si-detector` from the repository root. This installs `slither-analyzer==0.11.3` and registers MV-Scan through Slither's plugin entry point.

**Outputs:**
- `out/ablation_map.json`: ablation ID/name/env mapping
- `out/ablation_map.tsv`: TSV version of the mapping
- `out/done.tsv`: resumable run ledger
- `out/<label>/<ablation_id>/findings.json`: per-run detector JSON
- `out/<label>/<ablation_id>/slither_stdout.txt`: full analyzer output
- `out/<label>/<ablation_id>/meta.json`: structured run metadata

**Default ablations:**
- `baseline` is our reference configuration (B0)
- `no_init_only` is B1
- `no_admin_benign` is B2
- `sink_none` is B3
- `sink_samevar` is B4
- `budget_0` is B5
- `budget_inf` is B6

**Important notes:**

- If the script fails, the reason will still be written to `out/<label>/<ablation_id>/`, primarily evident in `slither_stdout.txt`. You can use this to debug the program as it may not support all shapes of smart contract repos.
- The main blocker for successfully running the detector on a repo is a failed framework compilation. Slither 0.11.3 provides native storage-layout support; the detector still also understands Hardhat/Foundry build-info artifacts when precise slot recovery is needed.
- Tracks successful runtime samples by ablation and overall.
- Prints average runtimes at the end, or after interruption.

---

## inconsistent_state (our Slither detector)

**Purpose:** The core program. Detects inconsistent-state shapes centered on cross-transaction stale-read and destructive-write behavior, while grouping entangled variables into multi-variable buckets. The detector is designed for MV-Scan experiments and emits both human-readable Slither findings and stable JSON for downstream usage.

**Major extensions beyond SV-SI:**
- Storage-slot alias resolution to eliminate false positives where distinct variables share a slot.
- Pseudo-variables for branch-groups and multi-return groups to model MV-SI structure.
- Reentrant and shared-callee shape tags to help downstream triage.
- Optional atomic grouping of entrypoints to support above-transaction merging.

**How it works:**

1. Builds a state-annotated ICFG over all derived contracts by visiting every function node and recording CFG blocks, successor edges, approximated call/return edges, per-block read/write sites, branch-group metadata, function returns, and function lookup tables. Suppresses creation-phase findings and identifies admin-only functions.
2. Synthesizes pseudo-variables for branch-groups with 2+ concrete state variables and functions whose returns expose multiple variables or pairs.
3. Builds call-graph edges over internal/external calls to later classify triage shapes.
4. Restricts analysis to user-callable public/external entrypoints, excluding constructors, common initializer/setup functions, and optionally role-gated/admin functions depending on flags.
5. Performs reachability pruning from user-callable entries to remove all unreachable CFG blocks and related read/write sites.
6. Enumerates raw stale-read pairs from the state-annotated ICFG. The B0 sink-context gate checks branch, call, or write-bearing blocks where the tracked state is read and reachable without overwrite; it is not full value propagation. Filters out benign admin-only writes, init-only variables, and init-latch cases.
7. Buckets surviving findings by transaction-set and variable identity are tagged with shape metadata. Findings are canonicalized, deduplicated, emitted, and JSON is saved if `ISD_JSON_OUT` is set.

**Detection model:**

The main reported classes (buckets) are:

- `single_var_cross_tx`: one variable across multiple transactions
- `multi_var_intra_contract`: multiple related variables declared within one contract
- `multi_var_cross_contract`: multiple related variables spanning more than one contract

Each bucket documents: the class, the variables, the transaction set, the representative writer and reader sites, operational shapes, and aggregate/per-variable shape tags.

**Usage:**

Prerequisite: install the detector plugin and ensure the target codebase compiles:

```bash
python3.10 -m pip install -e slither-si-detector
npx hardhat clean
npx hardhat compile
ISD_JSON_OUT=out.json slither . --detect inconsistent_state
```

The plugin pins `slither-analyzer==0.11.3`. The old Slither 0.9.2 workaround for manually preserving `storageLayout` is no longer required.

**Required setup for slot tracking:**
1. Prefer Slither 0.11.3's native storage-layout data.
2. If reproducing with precompiled Hardhat or Foundry artifacts, keep compiler metadata/build-info available so the detector's fallback slot scanner can read it.

**Environment variables:**

- `ISD_JSON_OUT`: path for machine-readable JSON output.
- `DIVERGENCE_BUDGET`: bounds forward slicing for sink analysis.
  - `0` disables traversal
  - positive integer bounds traversal
  - negative or `inf`/`unbounded` means no bound
- `SINK_TEST`: sink heuristic mode:
  - unset or anything else: no sink gating
  - `samevar`: same-variable reread at a critical sink
  - `value`: value-influence sink heuristic
- `USER_CALLABLE_ALWAYS`: comma-separated outer entry names always treated as user-callable.
- `USER_CALLABLE_DENY`: comma-separated outer entry names never treated as user-callable.
- `USER_CALLABLE_INCLUDE_ROLE_GATED=1`: keeps owner/role-gated public/external entries instead of filtering them out.
- `INIT_ONLY_FILTER=1`: enables suppression of findings proven to be init-only.
- `ADMIN_WRITES_BENIGN=1`: suppresses admin-write/user-read pairs treated as operationally benign.
- `COARSE_DEDUP=1`: enables coarse canonical deduplication by bucket shape rather than exact site identity.
- `ATOMIC_GROUP`: comma-separated outer entry names to merge into a single synthetic transaction-level entry named `ATOMIC_GROUP`.
- `MERGE_OVERLOADS=1`: normalizes `Contract.fn(args...)` to `Contract.fn` when grouping transaction identities.

**Inputs:**
- A successfully parsed Slither compilation unit. We support Hardhat, Foundry, and Brownie/Truffle.
- Contract build artifacts or compiler metadata exposing `storageLayout`, when precise slot recovery is desired.
- Solidity project artifacts from Hardhat or Foundry if slot recovery must fall back to build-info scanning.

**Outputs:**
- (stdout) Standard Slither findings, one per canonicalized bucket, containing:
  - bucket class
  - variables hit
  - transaction-set
  - representative write sites
  - representative read sites
- (file) JSON written to the path in `ISD_JSON_OUT`, when set.

**JSON finding structure:**

- `pattern`: one of the bucket classes
- `vars`: variable metadata objects
- `tx_set`: list of entry names
- `writers`: representative writer callsites with signature, selector, file, line
- `readers`: representative reader callsites with signature, selector, file, line
- `op_patterns`: operation-level patterns seen within the bucket
- `shape`: aggregate bucket-level shape flags
- `shape_by_var`: per-variable shape metadata

Variable metadata includes:
- `name`
- `kind`: `state`, `external`, `mapping_slot`, `multi_var_group`
- `slot`: for direct storage variables when resolved
- `base_slot` and `key`: for mapping-slot variables
- `members`: for multi-variable groups
- `branch_groups`: when a variable participates in branch-group structure

---

## dataset/info.py

**Purpose:** Computes contract/file statistics for each repo in the dataset.

**How it works:**

1. Enumerates each repo from `out/` and matches them against repo directories under the contracts root.
3. Scans each repo recursively for `.sol` and `.vy` source files.
4. For each file, we count non-empty LOC, record file size in bytes, and extract the first `pragma solidity ...;` line.
5. We then aggregate an exhaustive list of statistics from each repo:
   - contract/file count
   - total non-empty LOC
   - average LOC per file
   - median LOC per file
   - largest file size
   - total repos
   - total contracts/files
   - total non-empty LOC
   - mean / median / P90 contracts per repo
   - mean / median / P90 LOC per file
   - heaviest repo by file count
   - heaviest repo by LOC
   - largest single file
   - cross-repo duplicate filenames
   - Solidity pragma histogram

**Usage:**

Basic usage and formatting options are CSV or TSV:

``` bash
python3 repo_ascii_table.py --out ./out --contracts ./Web3Bugs/contracts # --tsv
```

**Arguments:**
- `--out`: path to the `out/` directory containing numeric repo IDs (default: `out`)
- `--contracts`: path to the dataset contracts root (default: `web3bugs/contracts`)
- `--extensions`: repeatable source extension filter (default: `.sol`, `.vy`)
- `--tsv`: prints per-repo stats as TSV instead of the formatted ASCII table

**Inputs:**
- An `out/` directory whose immediate numeric children correspond to repo IDs.
- A contracts root containing all repos.
- Source files with the configured extensions is optional.

**Outputs:**
- (stdout) A table of per-repo statistics.
- (stdout) Dataset statistics.

**Important notes:**
- Repo IDs present in `--out` but missing under `--contracts` are skipped and reported.
- LOC is counted as non-empty lines only.

---

## dataset/fails.py

**Purpose:** Scans `out/` for failed detector runs and reports incompletions.

**How it works:**

1. Walks `out/` and loads all `meta.json` files.
2. Marks a run as failed if any of the following hold:
   - `meta.json` is missing or invalid
   - `ok=false`
   - `rc != 0`
   - `status_line` begins with `ERR`
   - `findings.json` is missing
3. Records label, ablation ID, run name, return code, status, run directory, and failure reasons.
4. Also checks for run directories that should contain `meta.json` but don't, and reports them.

**Usage:**

Show all runs and optionally emit `json`:

```bash
python3 dataset/fails.py --all
python3 dataset/fails.py --json
```

**Arguments:**
- `--out-dir`: path to the `out/` directory (default: `out`)
- `--all`: include successful and unknown runs, not just failures
- `--json`: emit JSON instead of TSV-style text

**Inputs:**
- `out/<label>/<ablation>/meta.json`
- `out/<label>/<ablation>/findings.json` presence check

**Outputs:**
- (stdout) Failed runs, or all runs with `--all`
- (stderr) Final summary in the form `[SUMMARY] scanned=<n> runs, failures=<m>`

**Important notes:**
- Use this script to identify which ablations need reruns/debugging.

---

## dataset/tools/remove_failed_detections.py

**Purpose:** Filters `out/done.tsv` to only lines whose ablation/run field indicates they completed a run successfully.

**How it works:**

1. Resolves `out/done.tsv` relative to the script location.
2. Compiles a regex for the expected valid token shape of `\b\d+c/1/\d+r\b`.
3. Reads every line from `done.tsv` and only keeps lines matching. Overwrites `done.tsv` with the filtered result and prints how many invalid lines were removed and how many valid lines were kept.

**Usage:**

```bash
python3 dataset/tools/remove_failed_detections.py
```

**Inputs:**
- `out/done.tsv`

**Outputs:**
- Overwrites `out/done.tsv` with filtered contents.
- (stdout) Summary of removed and kept lines.

**Important notes:**
- This is a cleanup utility for `out/done.tsv` that removes malformed/failed entries.
- The filtering rule is regex-based so make sure your directories/files match before running.

---

## dataset/tests_left.py

**Purpose:** Reports which repos still exist under `Web3Bugs/contracts` but haven't been run under the ablation study.

**How it works:**

1. Collects all immediate numeric directory names under `Web3Bugs/contracts` and `out/`.
2. Computes a set difference between the contract folders present in the dataset minus folders already present in `out/`. Prints total contract folders, out folders, and missing folders.

**Usage:**

```bash
python3 dataset/tests_left.py
```

**Inputs:**
- `Web3Bugs/contracts`
- `out`

**Outputs:**
- (stdout) Counts and list of numeric repos missing from `out/`.

**Important notes:**
- It does not verify whether all ablations were completed, only those which have not yet been scanned.

---

## evaluation/master.py

**Purpose:** This script reproduces the 7 core CSV artifacts:
  - normalized_rows.csv
  - master_ablation_table.csv
  - master_by_kind.csv
  - master_exclusions.csv
  - master_conflicts.csv
  - master_union_coverage.csv
  - runtime_summary.csv

**Usage:**

```bash
python3 evaluation/master.py \
  --xlsx MV-Bench.xlsx \
  --results "dataset/results.tsv" \
  --ablation-map "dataset/out/ablation_map.tsv" \
  --out "evaluation/validation/"
```

**Notes:**
- `evaluation/validation` is a folder we suggest instantiating for direct comparison to our results. -->
