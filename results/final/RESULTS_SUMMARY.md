# Final evaluation results

These results use the frozen detector runs and samples. No detector run was repeated.
The planned 200-row Web3Bugs agreement review was skipped by the research team; no agreement statistic is reported.

## Web3Bugs candidate precision

| Configuration | Disabled component | Population | Audited | TP MV-SI | Nonbug | Precision | Wilson 95% CI | Delta vs. B0 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| B0 | none (reference) | 2868 | 400 | 82 | 318 | 20.5% | 16.8%–24.7% | +0.0 pp |
| A1 | branch-derived relations | 550 | 400 | 114 | 286 | 28.5% | 24.3%–33.1% | +8.0 pp |
| A2 | multi-return relations | 2636 | 400 | 73 | 327 | 18.2% | 14.8%–22.3% | -2.2 pp |
| A4 | precise mapping identity | 3502 | 400 | 94 | 306 | 23.5% | 19.6%–27.9% | +3.0 pp |
| A5 | contextual keys | 3007 | 400 | 77 | 323 | 19.2% | 15.7%–23.4% | -1.2 pp |

Across the audited structural union, 301 of 1270 buckets were labeled TP MV-SI; 969 were labeled NONBUG.
The full frozen union contains 6873 buckets. The coordinated samples merge to 1270 audited buckets; 376 audited buckets occur in more than one configuration sample.

## Historical ISU recovery

The two ISU reviewers disagreed on 52 of 116 findings. After adjudication: 64 MV-SI, 39 non-MVSI, and 13 insufficient-evidence findings.

Of the 64 adjudicated MV-SI findings, 62 had accepted builds (96.9% build coverage). MV-Scan strictly recovered 13 of 62 (21.0%); the 2 unaccepted-build cases are outside B and were not run.
