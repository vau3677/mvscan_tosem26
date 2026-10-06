# Compilation Freeze

Sealed at `2026-08-17T20:06:49.827724+00:00` after verification.

A build is accepted only when the exact-revision native production compilation exits successfully, emits artifacts, and does not mutate tracked benchmark source or configuration. Partial artifacts and nonzero exits are exclusions.

## Frozen coverage

| Dataset | Population | Accepted | Excluded |
|---|---:|---:|---:|
| ISU findings | 116 | 106 | 10 |
| Web3Bugs snapshots | 102 | 65 | 37 |

The 37 Web3Bugs exclusions are 14 partial post-compilation failures, 21 attempted failures, and 2 snapshots with incompatible compiler constraints.

The 10 ISU exclusions map to six unavailable exact Git revisions across Polynomial, Particle, Strateg, and Gemnify. Reconstructed, later, patched, npm-only, report-excerpt, and synthetic substitutes were not accepted as the audited Git revisions.

## Frozen artifacts

- `reports/FROZEN_COMPILATION_COHORT.csv`: all 171 accepted dataset items.
- `reports/COMPILATION_EXCLUSIONS.csv`: all 47 excluded items with direct reasons and evidence pointers.
- `freeze/F1_compilation_freeze.json`: counts, policy, and SHA-256 hashes sealing the ledgers.

The pre-verification draft is retained under `freeze/superseded/`; it is explicitly superseded because it referenced the repository's stale empty `benchmarks/web3bugs/accepted_cohort.csv` and undercounted accepted ISU repository revisions.
