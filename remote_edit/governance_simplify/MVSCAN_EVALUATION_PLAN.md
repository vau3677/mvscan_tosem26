# MV-Scan Evaluation Plan

## 1. Purpose

MV-Scan proposes multi-variable state inconsistency (MV-SI) candidates. The detector supplies evidence; human reviewers decide whether it describes a real semantic defect.

| Dataset | Evaluation question | Review unit |
| --- | --- | --- |
| ISU/TOSEM (116 published findings) | Does B0 recover independently reported MV-SI defects? | One published finding |
| Web3Bugs (accepted, buildable projects) | What proportion of candidates are genuine MV-SI, and what does each component contribute? | One evidence-preserving cross-configuration bucket |

ISU is a closed-list recovery study, not an open-ended candidate audit. Web3Bugs is the precision and ablation study.

## 2. Semantic decision

A candidate is `TP_MVSI` only when all five conditions hold:

1. At least two distinct persistent-state entities participate.
2. Evidence independent of detector co-use, naming, or proximity supports a semantic relationship.
3. A feasible transition updates a nonempty proper subset and can leave related state inconsistent.
4. Omitted state is read before reconciliation and affects control flow, a storage write, or an external effect.
5. The defect essentially depends on the relationship between multiple persistent entities rather than unary stale state.

Exploitability, attacker control, severity, and novelty are separate practical judgments.

## 3. Frozen execution evidence

Use the recorded revisions, accepted native builds, detector version, configurations, environment, and terminal run artifacts. Do not repair subject source or silently discard failures. A successful run must exit normally and produce complete, parseable detector JSON consistent with its manifest.

| ID | Meaning |
| --- | --- |
| B0 | Complete detector |
| A1 | Branch-derived relations disabled |
| A2 | Multi-return relations disabled; internal predicate-only comparator |
| A4 | Mapping-insensitive state identity |
| A5 | Contextual key/storage/sender/argument propagation disabled |

Seed 0 is authoritative. B0 seed 1 is a determinism sensitivity check. Compare canonical outputs for every subject successful under both seeds and list every mismatch. Existing detector runs are repeated only if detector semantics, source/build inputs, configuration semantics, or run acceptance changes.

## 4. ISU historical recovery

Two reviewers independently classify all 116 findings as `MV_SI`, `SV_SI`, `ISU_OTHER`, `OTHER`, or `INSUFFICIENT_EVIDENCE`, using the published finding and recovered source evidence. Preserve both decisions and adjudicate disagreements.

Only adjudicated `MV_SI` findings enter recovery. For each with an accepted build, a strict B0 match requires one candidate containing the semantic relation core, desynchronizing writer, correct written and omitted roles, required persistent read and sink, and compatible execution ordering. Additional relation members are allowed but recorded as over-approximation.

Report this census waterfall: 116 published findings; adjudicated MV-SI findings; MV-SI findings with accepted builds (`B`); strict B0 matches (`M`). The headline is `M/B`; analysis failures are misses. Give each exclusion or non-match one reason: unavailable source/version, build failure, analysis failure, missing relation, missing writer, incorrect roles, missing omitted read, missing sink, incompatible context, or incompatible ordering. A census receives no confidence interval.

## 5. Web3Bugs precision and ablations

### Candidate frame

Include first-party Solidity in the production build. Exclude paths whose components unambiguously designate tests, fixtures, mocks, harnesses, examples, vendored code, or dependencies. Unmatched first-party-looking source remains in scope.

A candidate is in frame only when its writer, every relation member used in the claim, and retained reader and sink evidence are in scope. Remove out-of-scope evidence before constructing identity. Record frame exclusions without semantic labels.

### Evidence-preserving identity

The structural-bucket identity includes dataset, subject, revision, writer owner/block, relation members and origins, written/omitted roles, reader owner/block/storage context, sink function/node/kind, transaction-context owners, key-equality constraints, relation arity, and entity kinds.

Only claims with the same material evidence share a label across configurations. Configuration, seed, detector-local ID, and immaterial line movement do not split a bucket; a change to origins, witnesses, roles, contexts, ordering, or sink evidence does.

### Deterministic sampling and review

For each configuration, review every bucket when its population is at most 400; otherwise select the 400 lowest values of `SHA-256("20260811" || global_candidate_id)`. Review the merged selected set once per unique bucket. Independently second-review the 200 lowest values of `SHA-256("20260811:agreement" || global_candidate_id)`.

Assign one label: `TP_MVSI`, `VALID_OTHER_ISU`, `NONBUG`, or `INSUFFICIENT_EVIDENCE`. Primary precision is `TP_MVSI / all reviewed buckets`; because insufficient evidence remains in the denominator, call it a conservative lower bound. Also report a resolved-case sensitivity excluding `INSUFFICIENT_EVIDENCE`.

Report B0 as the headline and A1/A2/A4/A5 separately. Use a finite-population, design-based 95% interval because sampling is without replacement. Treat cross-configuration differences as descriptive paired effects, not independent significance tests. Report raw agreement, Cohen's kappa, and the confusion matrix before adjudication.

## 6. Overlap, failures, and performance

The primary Web3Bugs analysis uses the full accepted cohort. Also report the declared non-overlap sensitivity that removes projects shared with ISU. Never remove overlap silently.

Precision is conditional on projects with successful analysis; report accepted, attempted, successful, and failed counts together. For every configuration report candidate and bucket counts, labels, precision and interval, runtime median/IQR/maximum, peak-RSS median/maximum, and failure types. External tools are not accuracy baselines unless they express the same semantic target on the frozen subjects; A2 is the internal comparator.

## 7. Required outputs

The evaluation is complete when the repository contains:

- immutable source/build/run evidence and manifests;
- the current source-scope table and cross-ablation union inventory;
- deterministic primary and agreement samples;
- two independent ISU classification sheets and adjudication;
- Web3Bugs labels, second-review labels, and adjudication;
- ISU strict-match decisions;
- scripts that regenerate the reported tables; and
- one `freeze/EVALUATION_SNAPSHOT.json` hashing the exact plan, inputs, derived cohorts, reviewer sheets, and analysis outputs used in the paper.

The reviewer entry point is `human_review/START_HERE.md`. Dataset guides explain only fields reviewers must complete. Historical plans, amendments, and superseded seals belong under `archive/governance/` and are not part of the current workflow.

## 8. Change rule

There are no F0/F1/F2 gates. Version control records ordinary edits; the single current snapshot records the evaluated state. Rebuild the sample only when the candidate frame, structural identity, population, or selection rule changes. Rerun detector executions only for the execution-semantic changes in Section 3. Documentation, validation, and table-generation corrections reuse immutable evidence.

Exploratory analyses must be labeled exploratory and may not replace primary measures. This document is the sole authoritative evaluation plan; amendments do not form a second track.
