# MV-Scan — TOSEM research artifact

MV-Scan is a Slither plugin that reports candidate multi-variable state
inconsistencies. It infers state relationships, identifies partial writes, and
attaches evidence of omitted-state consumption. Candidates require manual
validation; the detector does not prove path feasibility or exploitability.

## Publication-facing entry points

| Path | Purpose |
| --- | --- |
| [mvscan-smoke/mvscan_plugin/](mvscan-smoke/mvscan_plugin/) | Frozen detector implementation and configuration parsing |
| [mvscan-smoke/pyproject.toml](mvscan-smoke/pyproject.toml) | Plugin registration and pinned frontend dependencies |
| [mvscan-smoke/tests/](mvscan-smoke/tests/) | Current unit tests for roots, read/write pairing, witnesses, and freeze repairs |
| [mvscan-smoke/contracts/](mvscan-smoke/contracts/) | Small Solidity examples and regression subjects |
| [protocol/MVSCAN_EVALUATION_PLAN.md](protocol/MVSCAN_EVALUATION_PLAN.md) | Evaluation protocol and authoritative detector hashes |
| [runners/](runners/) | Paper-result and reviewer-material generators |
| [results/final/](results/final/) | Preserved paper-facing summary tables and note analysis |
| [manuscript/](manuscript/) | LaTeX paper, tables, bibliography, and pinned ACM template |
| [dataset/Web3Bugs/](dataset/Web3Bugs/) | Benchmark source, reports, and upstream evidence |
| [deliverables/](deliverables/) | Reviewer cards, source mapping, and validation handoff |
| [reviewer_handoff_ISU/](reviewer_handoff_ISU/) and [isu_annotator_2_packet/](isu_annotator_2_packet/) | Distinct historical-finding reviewer packets |

`dataset/Web3Bugs/excluded_contracts_from_ablations/` contains sources cited by
the current review materials. Preserve it. The additional Backd fee-handler and
AMM-gauge regression tests are research additions and must remain distinguishable
from the upstream snapshot.

## Install and run a small detector example

The plugin requires Python 3.10, Slither 0.11.3, and crytic-compile 0.3.11.
From the repository root:

```sh
python3.10 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./mvscan-smoke
python -m pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
slither mvscan-smoke/contracts/CorePredicateSmoke.sol \
  --detect inconsistent_state --solc-disable-warnings --fail-none
```

This is a small example, not a reproduction of the full study. The five study
configurations are B0, A1 (no branch-derived relations), A2 (no return-derived
relations), A4 (mapping-insensitive identity), and A5 (no contextual keys).
Their complete preserved settings are in
[remote_edit/runners/configuration.py](remote_edit/runners/configuration.py).
Do not substitute detector defaults or the archived seven-configuration scheme
for the study configuration.

For the current unit tests, install `pytest` in that environment and run:

```sh
python -m pytest mvscan-smoke/tests
```

For the manuscript build, see [manuscript/README.md](manuscript/README.md).

## Reproduction status

This checkout preserves the frozen detector, summary tables, and supporting
source and review materials. It does **not yet contain the complete study
reproduction bundle**. The finalized annotation/adjudication inputs, frozen
sample and union inventories, environment/configuration manifests, and recorded
run manifests referenced by the generators are missing from their expected
locations. Blank reviewer forms are not substitutes for finalized labels.

[remote_edit/](remote_edit/) contains preserved evaluation-runner versions,
frontend compatibility patches, and a deviation ledger. Several match the
frozen snapshot exactly. Retain these until the canonical reproduction layout
and missing inputs are restored. The staging directories are not independently
runnable study entry points, and the root generators currently have unresolved
imports and inputs.

The overlap note in `results/final/PAPER_TABLES.md` reports 156 shared sampled
buckets, while the manuscript reports 376. Resolve this from the original
membership sets before packaging; preserve both records meanwhile.

The separately maintained original-study repository under
`oracle/SolidityStateStudy/` and review UI under
`ideas/web3bugs_agreement_ui/` are excluded from this parent Git repository.
They remain local and are not included by cloning this repository.

## Historical archive

[archive/legacy/](archive/legacy/) preserves obsolete evaluation tooling,
development instructions, the old classification drivers and their fixtures,
debugging outputs, duplicate review cards, an ISU distribution ZIP, upstream
template examples, and a historical compiler patch. Their original paths and
verified SHA-256 hashes are recorded in
[MANIFEST.json](archive/legacy/MANIFEST.json).

[archive/reviewer_optimization/](archive/reviewer_optimization/) preserves a
historical reviewer-workflow snapshot and unique scripts. These archives are
research provenance, not current detector or study execution entry points.
No research files were deleted during this reorganization.
