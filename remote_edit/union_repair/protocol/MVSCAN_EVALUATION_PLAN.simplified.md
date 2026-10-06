# MV-Scan Evaluation Plan

## Purpose

MV-Scan is a static may-analysis that proposes multi-variable state
inconsistency (MV-SI) candidates. It identifies related persistent-state
entities, a transition that updates only part of that relation, and a later
read of omitted state that reaches a relevant operation. The detector proposes
evidence; humans decide whether the candidate represents a real semantic
inconsistency.

The evaluation uses two datasets for different purposes:

| Dataset | Question | Human-review unit |
| --- | --- | --- |
| ISU/TOSEM, 116 published findings | Does MV-Scan recover independently known MV-SI defects? | One published finding |
| Web3Bugs, accepted buildable projects | What proportion of detector candidates are genuine MV-SI, and how do components affect results? | One cross-configuration structural bucket |

ISU detector output is not used as an open-ended precision audit. Reviewers
classify the 116 known findings, and eligible MV-SI findings are checked for a
strict detector match. Web3Bugs supplies the detector-output precision and
ablation evaluation.

## Research questions and measures

1. **Historical recovery.** Among known ISU findings classified as MV-SI and
   successfully compiled, how many have a strict B0 match? Report `M/B`, where
   `B` is the buildable MV-SI denominator and `M` is the number strictly
   matched. Analysis failures count as misses.
2. **Candidate precision.** What proportion of audited Web3Bugs structural
   buckets are `TP_MVSI`? B0 is the headline estimate. A1, A2, A4, and A5 are
   reported separately with finite-population, design-based 95% confidence
   intervals.
3. **Component contribution.** How do A1, A2, A4, and A5 change historical
   matches, candidate volume, precision, runtime, and memory relative to B0?
4. **Practicality.** Report completion, failures, runtime, peak RSS, and exact
   seed-0/seed-1 B0 output agreement.

Every reported proportion includes its numerator, denominator, exclusions,
and failure counts. Validated practical findings are reported separately and
are not used as an accuracy measure.

## Semantic definition

A candidate is MV-SI only when all five conditions hold:

| Condition | Required evidence |
| --- | --- |
| **C1 — Multiple persistent entities** | At least two distinct persistent-state entities participate. Precise mapping/array locations and state-backed external values may qualify. Multiple names for one location do not. |
| **C2 — Protocol relation** | Independent source, documentation, test, report, economic, trace, or fix evidence supports a semantic relationship. Detector co-use, naming, or proximity alone is insufficient. |
| **C3 — Desynchronizing partial transition** | A feasible operation updates a nonempty proper subset of the relation and leaves related state stale or inconsistent. |
| **C4 — Consumption before reconciliation** | Omitted persistent state is read before reconciliation and affects `control`, `storage_write`, or `external_effect`. Dead, logging-only, or outcome-insensitive reads do not qualify. |
| **C5 — Multi-variable essentiality** | The defect essentially depends on the relationship between at least two persistent entities rather than being a unary stale-state defect. |

Exploitability, attacker control, severity, and novelty are separate practical
judgments and are not required for semantic MV-SI.

## Subjects and execution

Use the frozen source revisions, accepted native builds, detector version,
configurations, and run manifests already recorded in the artifact. Solidity
sources and checked-in build logic are not repaired for evaluation. Source or
build failures remain visible as exclusions.

The evaluated configurations are:

| ID | Change from B0 |
| --- | --- |
| **B0** | Complete detector |
| **A1** | Disable branch-derived relations |
| **A2** | Disable multi-return relations |
| **A4** | Use mapping-insensitive state identity |
| **A5** | Disable contextual key/storage/sender/argument propagation |

A2 is the internal predicate-only comparator. External tools are not treated
as accuracy baselines unless they express the same semantic target on the
same frozen subjects; target or capability mismatches are stated explicitly.

Runs use the recorded Linux environment, compiler/toolchain selected from
project evidence, four CPUs, 32 GiB memory, a 900-second build timeout, and an
1,800-second analysis timeout. Analysis runs are offline. Each terminal run
records source/build/environment identities, command, configuration, resource
limits, status, runtime, peak RSS, and raw/canonical output digests.

A successful run must exit normally and produce complete, parseable detector
JSON consistent with its manifest. Timeout, OOM, context-bound, parse, and
other analysis failures are reported rather than silently discarded.
Seed 0 is authoritative. B0 seed 1 is a determinism sensitivity run and never
silently replaces seed-0 output.

## ISU historical recovery

Two reviewers independently classify each of the 116 published findings as:

```text
MV_SI
SV_SI
ISU_OTHER
OTHER
INSUFFICIENT_EVIDENCE
```

Disagreements are adjudicated while preserving the two original decisions.
Only findings finally classified as `MV_SI` enter the recovery question.
The initial packets contain the published finding and recovered source evidence;
B0 candidate packets are generated only after semantic adjudication so the
classification decision is not influenced by detector output.

For every buildable MV-SI finding, a strict match requires one detector
candidate that contains the required semantic relation core, the actual
desynchronizing writer, correct written and omitted roles, the required
persistent read and sink, and compatible execution ordering. Additional
detector relation members are allowed but recorded as over-approximation.

Report the following waterfall:

```text
116 published findings
semantic MV-SI findings
MV-SI findings with accepted builds (B)
strict B0 matches (M)
```

Classify each non-match or exclusion with one primary reason: unavailable
source/version, build failure, analysis failure, missing relation, missing
writer, incorrect roles, missing omitted read, missing sink, incompatible
context, or incompatible ordering. Historical recovery is a census and does
not receive a confidence interval.

## Web3Bugs precision and ablations

### Candidate frame

Include first-party Solidity in the ordinary production build. Exclude paths
whose components unambiguously designate tests, testing, mocks, fixtures,
harnesses, examples, vendored code, libraries, or dependencies, as well as
dependency-package paths. Unmatched first-party-looking source remains in
scope.

A candidate enters the precision population when its writer and every relation
member used by the claim are in scope, at least one relation origin is in
scope, and at least one witness has an in-scope reader and sink. Remove
out-of-scope origins, witnesses, and sinks before constructing identity. Count
frame exclusions without assigning semantic labels.

### Cross-configuration deduplication

The review unit is a structural bucket, not a raw report or individual witness.
Create a canonical payload containing:

- dataset, subject, and revision;
- writer owner and writer block;
- relation-member identities;
- written and omitted-member identities;
- relation-origin function, block, and expression;
- reader file, line, signature, block, owner, and storage context;
- sink function, node, and kind;
- transaction-context owners and key-equality constraints; and
- relation arity and entity kinds.

The SHA-256 of that payload is `global_candidate_id`. Configuration, seed,
and detector-local ID do not split a bucket. A meaningful change to relation
origin, state identity, written/omitted roles, reader evidence, context,
ordering evidence, or sink identity does split it. One human label is reused
only where the material claim and evidence are the same across configurations.

### Sampling

For each configuration independently, select all buckets when its population
is at most 400; otherwise select the 400 lowest values of:

```text
SHA-256("20260811" || global_candidate_id)
```

Merge the five selected sets and review each unique bucket once. The corrected
frame and evidence-preserving identity produce 1,270 unique Web3Bugs review
units from a union of 6,873 buckets. Select the 200
lowest values of `SHA-256("20260811:agreement" || global_candidate_id)` for an
independent second review.

### Candidate labels

Assign exactly one label:

```text
TP_MVSI
VALID_OTHER_ISU
NONBUG
INSUFFICIENT_EVIDENCE
```

`TP_MVSI` requires C1–C5. `VALID_OTHER_ISU` records a real state inconsistency
outside the complete MV-SI definition. `INSUFFICIENT_EVIDENCE` remains in the
primary denominator, so the primary estimate is described as a conservative
lower bound; also report a resolved-case sensitivity excluding that label. For
`NONBUG`, record one primary cause from the frozen
annotation schema. Reviewers record C1–C5, confidence, and a short evidence
note. The second reviewer works independently; report raw agreement, Cohen's
kappa, and the confusion matrix before adjudication.

The primary analysis retains all accepted Web3Bugs projects. A declared
non-overlap sensitivity removes projects that overlap the ISU subject set;
overlap is never removed silently. Precision is conditional on projects with
successful analysis, so accepted, successful, and failed counts are reported
together.

## Determinism, performance, and reporting

Compare B0 seed 0 and seed 1 by exact canonical-output digest for every subject
where both runs succeeded. List every mismatch. Report per configuration:

```text
subjects attempted and successful
native candidate and structural-bucket counts
TP_MVSI and other label counts
precision with finite-population, design-based 95% interval
median, IQR, and maximum runtime
median and maximum peak RSS
timeout, OOM, context-bound, and other failures
```

Because configuration samples share projects and structural buckets,
cross-configuration deltas are paired descriptive effects rather than
independent-sample significance tests.

The paper should need approximately six tables: population/build coverage;
ISU classification and recovery; Web3Bugs labels and precision; cross-ablation
overlap and effects; determinism/performance; and error analysis with practical
findings kept separate.

## Reproducibility and change control

The evidence required to reproduce reported results is:

- detector and configuration identities;
- source revisions and accepted-build records;
- terminal run manifests and raw/canonical outputs;
- the structural-union definition and deterministic sample IDs;
- original annotations, adjudications, and strict-match decisions; and
- scripts that regenerate reported tables from those artifacts.

`freeze/EVALUATION_SNAPSHOT.json` is the single checksum manifest for the
current evaluation state. Earlier F1/F2 launch seals are retained only under
`archive/governance/`; they are historical execution records, not current
conceptual stages or reviewer obligations.

A change requires rerunning detector executions only when it changes detector
semantics, evaluated source/build inputs, configuration semantics, or run
acceptance. A change requires a new sample only when it changes the candidate
frame, structural identity, population, or selection rule. Corrections to
documentation, presentation, validation, or table-generation code are recorded
in version control and rerun only against existing immutable evidence.

Exploratory analyses must be labeled exploratory and may not replace the
predeclared primary measures. That is the full governance requirement.

## Current artifact locations

```text
human_review/                         reviewer-only materials
benchmarks/                           populations, sources, builds, evidence
runs/                                 terminal detector attempts
freeze/CROSS_ABLATION_UNION_INVENTORY.json
freeze/CROSS_ABLATION_SAMPLE.json
freeze/DETERMINISM_REPORT.json
freeze/EVALUATION_SNAPSHOT.json       current-state checksum manifest
runners/                              construction and analysis scripts
tests/                                infrastructure checks
archive/legacy/                       historical implementation, not current
archive/governance/                   superseded launch/seal machinery
```
