# Compilation Freeze

Sealed at `2026-08-17T20:05:39.474211+00:00`.

The compilation cohorts are frozen under the exact-revision, no-edit acceptance rule. A build is accepted only when its native production compilation exits successfully, emits artifacts, and does not mutate tracked benchmark source or configuration. Partial artifacts and nonzero exits remain exclusions.

## Frozen coverage

| Dataset | Population | Accepted compilation | Excluded |
|---|---:|---:|---:|
| ISU findings | 116 | 106 | 10 |
| Web3Bugs snapshots | 102 | 65 | 37 |

Web3Bugs exclusions comprise 14 partial post-compilation failures, 21 attempted failures, and 2 explicit incompatible-compiler snapshots.

ISU's 10 excluded findings map to six unavailable exact Git revisions across Polynomial, Particle, Strateg, and Gemnify. Reconstructed, later, patched, npm-only, report-excerpt, and synthetic substitutes were not treated as the audited Git revisions.

The complete per-item reason register is `reports/COMPILATION_EXCLUSIONS.csv`. The machine-readable seal and hashes are in `freeze/F1_compilation_freeze.json`.
