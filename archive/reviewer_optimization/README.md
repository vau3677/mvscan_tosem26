# MV-Scan Evaluation Repository

This repository contains the frozen MV-Scan evaluation over the ISU/TOSEM and
Web3Bugs datasets. Compilation and detector execution are complete. The
existing F1/F2 files preserve checksums for the executed study; the concise
current plan explains the scientific design without requiring readers to
follow the historical sealing workflow.

## Start here

- Human reviewers: use only `human_review/START_HERE.md`.
- Evaluation protocol: `protocol/MVSCAN_EVALUATION_PLAN.md`.
- Historical checksum manifests: `freeze/F1_SEALED.json` and `freeze/F2_SEALED.json`.
- Current orchestration and validation code: `runners/` and `tests/`.
- Run artifacts: `runs/`.
- Canonical datasets, evidence, builds, and subject manifests: `benchmarks/`.

## Current structure

```text
benchmarks/   canonical populations, evidence, builds, and subject manifests
configs/      B0 and A1/A2/A4/A5 configurations
detector/     frozen detector identity
deviations/   evaluation deviation ledger
environment/ frozen compiler and execution environment
freeze/       frozen outputs, samples, and archival checksum manifests
human_review/ minimal role-separated reviewer interface
protocol/     current evaluation and annotation rules
reports/      machine-generated operational reports
runners/      current evaluation tooling
runs/         immutable terminal detector attempts
schemas/      machine-readable schemas
tests/        evaluation-infrastructure tests
```
