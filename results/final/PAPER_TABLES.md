# Paper-facing result tables

## Table 1. Benchmark populations and best-effort no-edit build coverage.

| Benchmark | Initial Population | Exact Source Revision Resolved | Accepted Builds | Excluded Or Unbuilt | Build Coverage |
| --- | --- | --- | --- | --- | --- |
| Published ISU findings | 116 | 116 | 106 | 10 | 91.4% |
| Web3Bugs snapshots | 102 | 102 | 65 | 37 | 63.7% |

*Note:* ISU build coverage here covers all 116 findings; Table 2 reports coverage within adjudicated MV-SI cases.

## Table 2. Historical ISU classification and strict semantic recovery.

| Historical Findings | Mv Si | Non Mvsi | Insufficient Evidence | Mv Si With Accepted Build | Strict Matches | Strict Recovery | Exact Fix Controls Eligible | Exact Fix Controls Run |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 116 | 64 | 39 | 13 | 62 | 13 | 21.0% | 0 | 0 |

*Note:* Only accepted-build MV-SI cases enter the strict-recovery denominator. No exact fixed revisions were predeclared, so no exact-fix control was eligible.

## Table 3. Candidate labels and per-configuration precision.

| Configuration | Audited | Tp Mvsi | Valid Other Isu | Nonbug | Insufficient Evidence | Precision | Wilson 95 Ci | Agreement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | 400 | 82 | 0 | 318 | 0 | 20.5% | [16.8%, 24.7%] | Skipped; not reported |
| A1 | 400 | 114 | 0 | 286 | 0 | 28.5% | [24.3%, 33.1%] | Skipped; not reported |
| A2 | 400 | 73 | 0 | 327 | 0 | 18.2% | [14.8%, 22.3%] | Skipped; not reported |
| A4 | 400 | 94 | 0 | 306 | 0 | 23.5% | [19.6%, 27.9%] | Skipped; not reported |
| A5 | 400 | 77 | 0 | 323 | 0 | 19.2% | [15.7%, 23.4%] | Skipped; not reported |

*Note:* Wilson intervals are computed separately. Agreement was skipped by team decision and must not be reported as zero.

## Table 4. Cross-ablation candidate populations and configuration-specific buckets.

| Configuration | Native Candidates | In Scope Structural Buckets | Audited Buckets | Configuration Only Population | Configuration Only Audited | Configuration Only Tp Mvsi | Precision Delta Vs B0 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | 3732 | 2868 | 400 | 154 | 24 | 5 | +0.0 pp |
| A1 | 688 | 550 | 400 | 324 | 237 | 53 | +8.0 pp |
| A2 | 3370 | 2636 | 400 | 326 | 48 | 10 | -2.2 pp |
| A4 | 4735 | 3502 | 400 | 2100 | 251 | 70 | +3.0 pp |
| A5 | 3725 | 3007 | 400 | 1254 | 171 | 33 | -1.2 pp |

*Note:* The frozen union contains 6873 buckets; the five samples merge to 1270, including 156 sampled buckets shared across configurations.

## Table 5. Completion, runtime, memory, and deterministic reproducibility.

| Benchmark | Configuration | Attempted | Successful | Completion | Runtime Median S | Runtime Iqr S | Runtime Max S | Peak Rss Median Mib | Peak Rss Max Mib | Timeouts | Oom | Context Bound | Seed Pairs | Exact Seed Matches | Seed Mismatches | Missing Seed Pairs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| isu | B0 | 88 | 88 | 100.0% | 12.90 | 5.80–23.03 | 659.39 | 332.9 | 15534.9 | 0 | 0 | 0 | 80 | 76 | 4 | 8 |
| isu | A1 | 88 | 88 | 100.0% | 11.42 | 5.61–21.58 | 316.72 | 322.5 | 5167.7 | 0 | 0 | 0 | — | — | — | — |
| isu | A2 | 88 | 88 | 100.0% | 12.67 | 5.80–22.90 | 396.66 | 321.1 | 8327.4 | 0 | 0 | 0 | — | — | — | — |
| isu | A4 | 88 | 88 | 100.0% | 14.73 | 5.96–22.65 | 420.74 | 340.3 | 9155.9 | 0 | 0 | 0 | — | — | — | — |
| isu | A5 | 88 | 88 | 100.0% | 12.82 | 5.78–21.89 | 502.09 | 331.2 | 12529.7 | 0 | 0 | 0 | — | — | — | — |
| web3bugs | B0 | 65 | 61 | 93.8% | 7.61 | 3.84–20.99 | 59.58 | 237.0 | 1047.4 | 0 | 0 | 0 | 61 | 61 | 0 | 4 |
| web3bugs | A1 | 65 | 61 | 93.8% | 7.31 | 3.74–14.78 | 58.32 | 229.2 | 1044.1 | 0 | 0 | 0 | — | — | — | — |
| web3bugs | A2 | 65 | 61 | 93.8% | 7.60 | 3.84–18.49 | 59.72 | 231.4 | 1046.8 | 0 | 0 | 0 | — | — | — | — |
| web3bugs | A4 | 65 | 61 | 93.8% | 8.06 | 3.84–20.90 | 64.88 | 244.5 | 1048.5 | 0 | 0 | 0 | — | — | — | — |
| web3bugs | A5 | 65 | 61 | 93.8% | 7.61 | 3.79–20.20 | 59.72 | 233.1 | 1043.0 | 0 | 0 | 0 | — | — | — | — |

*Note:* Runtime and RSS preserve frozen successful seed-0 runs and use accepted compatibility-recovery runs only for subjects that originally failed. Determinism columns apply only to the frozen B0 seed-0/seed-1 comparison.

## Table 6. Primary causes of Web3Bugs nonbugs and separately validated findings.

| Category | Count | Share Of Nonbugs |
| --- | --- | --- |
| No desynchronizing partial transition | 522 | 53.9% |
| Reconciliation precedes consumption | 291 | 30.0% |
| Analysis abstraction error | 104 | 10.7% |
| Unsupported or overbroad relation | 31 | 3.2% |
| Incompatible context/key/ordering | 20 | 2.1% |
| Omitted state not behaviorally consumed | 1 | 0.1% |
| Separately consolidated and validated new findings | — | Not yet determined; validation stage not performed |

*Note:* The 301 TP_MVSI structural buckets are candidate-level classifications, not consolidated novel findings.
