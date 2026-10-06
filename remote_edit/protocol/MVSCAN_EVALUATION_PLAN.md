# MV-Scan Evaluation Plan

MV-Scan is a static may-analysis for candidate multi-variable state inconsistency (MV-SI). It infers relations between persistent-state entities. It identifies a writer that updates a nonempty proper subset of a relation. Then, it attaches evidence that a member omitted by the writer is read from persistent state and influences a modeled sensitive operation. MV-Scan does not establish a protocol invariant, path feasibility, attacker control, or exploitability. That is done manually by a human.

This document freezes the evaluation protocol for MV-Scan. The protocol is intentionally limited to evidence that directly supports the detector's stated contribution.

## Detector identity and evaluation targets

Any change to a frozen detector file creates a new detector version and requires all affected runs to be repeated. These hashes are authoritative:

| Module | SHA-256 |
| --- | --- |
| `inconsistent_state.py` | `83999325fe57207d770a02bfb61a0a4389a5d1faeab4a1360d2975aef438c14c` |
| `icfg.py` | `4c26fe2f758da22c1f9710ccd58681e59c687ab2a793fe292d453ca97c0f742b` |
| `mvscan_env.py` | `dd9b7bd80f859c91d7820cb2502b7f79027a40938b6a57f4bbee9ea54bcdc176` |

The evaluation has two targets:

1. **Historical benchmark:** all 116 documented inconsistent-state-update cases in the frozen SolidityStateStudy artifact.
2. **Independent candidate cohort:** the accepted, buildable projects in the frozen Web3Bugs source population.

Evaluation infrastructure may acquire and build subjects, invoke the detector, validate and canonicalize output, select samples, support annotation, compute frozen measures, and generate tables. It must not change detector semantics or benchmark Solidity source.

## Research questions and primary measures

### RQ1 — Historical recovery

**Among independently adjudicated and buildable historical MV-SI cases, how many does MV-Scan recover under a predeclared semantic match?**

Primary measure: `M / B`, where `B` is the number of adjudicated historical MV-SI rows with an accepted build and `M` is the number of those rows with a complete semantic match. Analysis failures remain in `B` and count as misses.

### RQ2 — Candidate precision

**What proportion of native MV-Scan candidates in the independent Web3Bugs cohort satisfy C1 through C5?**

Primary measure: `TP_MVSI / all audited native candidates`. `VALID_OTHER_ISU`, `NONBUG`, and `INSUFFICIENT_EVIDENCE` remain in the denominator.

### RQ3 — Component contribution

**How do the core relation-inference and state-identity mechanisms affect historical recovery and native candidate volume?**

Primary evidence: historical semantic matches, native candidate count, successful analyses, runtime, and peak memory for B0 and A1, A2, A4, and A5.

### RQ4 — Practicality and reproducibility

**What are MV-Scan's completion rate, runtime, peak memory, and deterministic reproducibility?**

Primary evidence: completion rate; median, IQR, and maximum runtime; median and maximum peak RSS; timeout, OOM, and context-bound counts; and exact canonical-output equality between B0 seed 0 and seed 1.

Validated findings are reported separately as descriptive results. They are not an RQ or an accuracy measure. Systematic limitations are reported in error analysis and the discussion.

## Claim-to-evidence matrix

Each central claim maps to a primary RQ and measure. Measurements without a direct mapping are excluded from the protocol.

| Manuscript claim | RQ | Primary evidence |
| --- | --- | --- |
| MV-Scan recovers known MV-SI defects | RQ1 | `M / B` semantic historical recovery |
| Native MV-Scan candidates identify semantic MV-SI | RQ2 | `TP_MVSI / all audited native candidates` |
| Relation inference and state identity materially affect results | RQ3 | B0-versus-A1/A2/A4/A5 recovery and candidate-count deltas |
| MV-Scan is executable and reproducible on the cohort | RQ4 | completion, runtime, RSS, failures, and seed equality |

Build coverage, the recovery waterfall, agreement, full-versus-clean sensitivities, error categories, exact-fix controls, and validated findings are supporting evidence.

## Semantic contract

For an inferred relation `R`, MV-Scan emits a native candidate only when `|R| >= 2`, `empty set < W < R`, and `O = R - W`, where `W` is the effective written subset and `>=1` member of omitted set `O` has a persistent-state read that influences a modeled sensitive operation. Emission is necessary but not sufficient for semantic MV-SI.

Manual evaluation must establish C1 through C5. Exploitability, attacker control, impact, and severity are assessed separately for practical findings and are not required for semantic MV-SI classification.

| Condition | Definition |
| --- | --- |
| **C1: Multiple persistent entities** | `>=2` persistent-state variables participate in the defect. "Variables" may be scalar state variables, precise mapping or array locations, semantically distinct slots of one base mapping, or state-backed values obtained through external view calls when independent evidence shows that they represent persistent protocol state. Multiple names for one logical location do not satisfy C1. |
| **C2: Protocol relation** | Independent evidence must support a semantic relationship among the participating variables. Acceptable evidence includes protocol logic, documentation, tests, reports, economics, a proof of concept, a concrete trace, comments corroborated by behavior, or the documented rationale for a fix. Detector co-influence, a shared branch or return, naming similarity, and proximity are insufficient by themselves. An emitted relation may contain a semantic core of `>=2` variables; additional emitted members are recorded as over-approximation. |
| **C3: Desynchronizing partial transition** | A feasible operation changes a nonempty proper subset of the semantic relation, leaves `>=1` related entity unreconciled, and makes the relationship stale, violated, or otherwise inconsistent. It fails C3 when the omitted entity is independent, the intermediate state is permitted, reconciliation necessarily precedes relevant use, the write is a semantic no-op, or writer and reader cannot occur in one protocol execution. Feasibility requires at least one valid state, call sequence, actor set, and required external conditions, not an unprivileged attacker. |
| **C4: Omitted-member consumption before reconciliation** | `>=1` omitted relation member is read from persistent state after the desynchronizing transition and before reconciliation, and that read reaches a behaviorally relevant modeled `control`, `storage_write`, or `external_effect` sink. Record the omitted entity, exact read, consumer, sink, ordering, reconciliation point, transaction relationship, and behavioral relevance. Logging, debugging, dead computation, and outcome-insensitive uses fail C4. |
| **C5: Multi-variable essentiality** | The defect must depend essentially on the relationship between `>=2` persistent-state variables. A unary stale-variable defect fails C5 even when additional emitted entities are incidental. |

The historical semantic classes are `MV_SI`, `SV_SI`, `ISU_OTHER`, `OTHER`, and `INSUFFICIENT_EVIDENCE`. Two independent annotators classify all 116 historical rows without inspecting final detector output. Original labels are immutable; disagreements produce separate adjudication records.

## Evaluation units and identifiers

The primary precision unit is the native writer-centered candidate: writer root, writer block, relation family, effective written subset, and omitted subset. Reader witnesses are evidence attached to that candidate. A practical finding may consolidate multiple candidates, witnesses, compilation units, or variants and is never substituted for the precision unit.

Each run identifier includes dataset, subject, revision role, configuration, Python hash seed, and repetition. A global candidate identifier includes run ID, compilation-unit ID, and detector candidate ID. Raw detector candidate IDs are not assumed globally unique.

## Source scope and candidate frame

The binary source rule:

`IN_SCOPE`: First-party Solidity source included in the project's ordinary production build.
`OUT_OF_SCOPE`: A separately versioned dependency, or a source explicitly designated as test/fixture by the project's native build configuration.
Unknown first-party sources remain `IN_SCOPE`.

A candidate enters the precision frame when its writer is in scope; it has at least one in-scope relation origin; and it has at least one in-scope reader witness and sink. The F1 manifest records the source evidence used by this rule before semantic candidate inspection. Frame exclusions are counted but are not assigned candidate labels.

## Freeze governance

| Freeze | Timing | Frozen material |
| --- | --- | --- |
| **F0: Detector** | Before this protocol | Detector files and exact hashes |
| **F1: Protocol** | Before final candidate payload inspection | benchmark commits, build commands, source scope, exposure flags, C1-C5 guide, minimal historical oracle, B0 and A1/A2/A4/A5, resource limits, sampling seeds and sizes, runner, and validator |
| **F2: Raw output** | After planned runs and deterministic selection, before candidate annotation | raw and canonical output, manifests, failures, hashes, selected sample IDs, and deviations |
| **F3: Results** | After annotation, adjudication, computation, and independent audit | original and final labels, evidence records, computed measures, tables, claims, and deviation history |

Raw outputs, original annotations, disagreement records, and adjudications are immutable. Corrections create new versioned artifacts. Before F2, researchers may inspect configuration, hashes, counts, status codes, stack traces, and other nonsemantic diagnostics, but not candidate source locations or semantic evidence. Any unavoidable pre-freeze exposure is recorded as described below.

## Historical benchmark

```text
Repository: HumblePLSE/SolidityStateStudy
Commit:     985e0032449aaa4fec4b6d2f9f7902525cbbb736
Population: 116 documented ISU cases
Unit:       one documented historical finding
```

The canonical population manifest has exactly 116 rows and preserves case identity, artifact paths, report evidence, source repository, vulnerable revision, exact fixed revision when available, affected location, evidence digest, and the exposure fields defined below.

### Build reconstruction and no-edit rule

Vulnerable revisions are selected from explicit artifact or report evidence. A build is accepted only when the declared affected source is present, the native production target compiles under the frozen environment, and the resulting compilation unit contains the affected contract and function when identified.

No Solidity source file, source pragma, project logic, lockfile, or checked-in build configuration may be edited. Allowed actions are dependency acquisition, selecting an already-permitted toolchain version, setting documented environment variables, and invoking an existing build command. Any subject requiring another modification is a build failure.

There is no repair identifier or case-specific repair catalog.

### Minimal semantic-match oracle

After independent historical adjudication and before final detector-output inspection, each `MV_SI` row receives this record:

```text
oracle_row_id
required_relation_core
required_writer_transition
required_written_roles
required_omitted_roles
required_persistent_read
required_sink_kind
required_ordering
reconciliation_point
evidence_references
```

Global semantic-match rules are:

- A relation passes when it contains every required semantic-core entity. Extra emitted members do not fail recovery and are recorded as over-approximation.
- An entity matches only the same canonical declaration or precise mapping location.
- Source renaming in an exact vulnerable/fixed pair may be mapped through the source diff.
- The writer identifies the actual desynchronizing assignment or call transition.
- The omitted read is the required persistent entity.
- The detector serializes a modeled sink reached by that read.
- One serialized witness must provide a feasible execution under the global C1-C5 rules.
- Context and ordering must be compatible with the documented defect.

There are no case-specific accepted aliases, incidental members, origin lists, equivalent roots, storage contexts, direct feeders, or equivalent writer-transition lists.

### Recovery and diagnostic waterfall

Define:

```text
H = historical rows adjudicated as MV_SI
B = rows in H with an accepted build
M = rows in B with a complete semantic match

build coverage       = B / H
historical recovery  = M / B
```

An analysis timeout, exception, malformed output, context-bound failure, or OOM counts as a miss in `M / B`. Historical recovery is a census and receives no confidence interval. Waterfall stages are diagnostic counts, not additional recovery measures. Use these mutually exclusive primary false-negative or attrition causes:

```text
source_or_version_unavailable
build_failure
analysis_failure
relation_not_recovered
writer_not_recovered
written_omitted_roles_wrong
omitted_read_not_recovered
sink_not_recovered
context_incompatible
ordering_incompatible
```

### Fixed revisions and exposure sensitivity

Run a fixed-revision negative control only when the report or artifact supplies an exact fix commit or merged fix pull-request revision. Do not search for the earliest descendant containing an inferred fix. Report vulnerable/fixed comparison in the historical classification-and-recovery table. Each row records only `pre_freeze_exposure = true | false` and `exposure_note`. Report the full historical result and one sensitivity excluding exposed rows. Do not create separate implementation, configuration, calibration, or debugging exposure cohorts.

## Web3Bugs cohort

Freeze the source repository, revision, population, ordinary production build command, permitted toolchain, and build outcome for every snapshot before candidate inspection. Apply the same no-edit build rule used by the historical benchmark. The accepted cohort is every snapshot that passes the predeclared build acceptance checks; all failures and reasons remain visible in population accounting. Record benchmark overlap or detector/calibration exposure with the same Boolean and evidence note: `pre_freeze_exposure = true | false` and `exposure_note`. Report only two cohort views:

`FULL`: The complete accepted Web3Bugs cohort.
`CLEAN`: `FULL` excluding any snapshot with recorded benchmark overlap or pre-freeze detector/calibration exposure.
FULL is the primary cohort. CLEAN is the sole exposure sensitivity.

## Candidate annotation

Assign every audited native candidate exactly one label: `TP_MVSI`, `VALID_OTHER_ISU`, `NONBUG`, `INSUFFICIENT_EVIDENCE`.

`TP_MVSI` requires C1-C5. `VALID_OTHER_ISU` is a real state-inconsistency issue outside the complete MV-SI definition. It remains a descriptive label and is neither a true positive nor an alternative success measure. `INSUFFICIENT_EVIDENCE` is used only after the frozen evidence search is exhausted and remains in the primary precision denominator.

For every audited candidate also record `protocol_relation_supported = YES | NO | UNCERTAIN`. This field supports C2 and error analysis; it is not a separate relation-fidelity RQ or estimator. Assign one primary cause to each `NONBUG` candidate:

```text
unsupported_or_overbroad_relation
no_desynchronizing_partial_transition
reconciliation_precedes_consumption
omitted_state_not_behaviorally_consumed
incompatible_context_key_or_ordering
analysis_abstraction_error
```

`VALID_OTHER_ISU` is outside this taxonomy. Secondary explanatory tags may be preserved in artifact data but are not manuscript outcomes. Annotation uses source, documentation, tests, reports, exact fixes, and witness-local detector evidence. Original labels are preserved before adjudication. Candidate precision and consolidated practical findings remain separate.

## Equal-probability sampling and agreement

Let `N` be the number of native candidates in the FULL in-scope B0 frame.

```text
If N <= 400: audit all candidates.
Else: compute SHA-256("20260811" || global_candidate_id) and select 400 candidates with the lowest digest.
```

Every candidate has equal inclusion probability. There are no certainty items, strata, allocation weights, cap inflation, or snapshot-specific quotas. A sample of 400 has an approximately +/-4.9 percentage-point worst-case margin at 95% confidence. For independent agreement review, select up to 200 candidates from the primary audited sample using the lowest values of a second domain-separated digest: `SHA-256("20260811:agreement" || global_candidate_id)`

Report raw agreement, Cohen's kappa, and the confusion matrix. Do not use design weights or a bootstrap interval for kappa. The primary candidate precision receives a Wilson 95% interval. A resolved precision excluding `INSUFFICIENT_EVIDENCE` may appear once in an appendix as a sensitivity, not as a co-primary result. Do not report combined MV-SI-plus-other-issue yield, macro precision, shape-specific precision, or snapshot-weighted precision.

## B0 and component ablations

The scientific description of B0 contains only its active semantics:

1. control- and multi-return-derived relation hypotheses;
2. precise mapping-location identity;
3. contextual key, storage, sender, and argument propagation;
4. no-op-write suppression; and
5. external-view state modeling.

The complete environment remains frozen in the machine-readable run manifest. Inert knobs, optional gates disabled by B0, and project-specific overrides are not presented as detector mechanisms or evaluation decisions.

We run these configurations for the paper:

| ID | Change from B0 | Mechanism tested |
| --- | --- | --- |
| **B0** | none | complete frozen detector |
| **A1** | disable branch-derived relations | control-derived relation inference |
| **A2** | disable multi-return relations | multi-return relation inference |
| **A4** | mapping-insensitive state identity | precise mapping-location identity |
| **A5** | disable contextual keys | contextual key, storage, sender, and argument propagation |

Run each configuration on every accepted historical vulnerable revision and Web3Bugs snapshot with identical source, build artifacts, toolchain, resource limits, and seed 0. For each configuration report:

```text
historical semantic matches
native candidate count
successful analyses
runtime
peak memory
```

Using the already annotated B0 sample, also report how many sampled B0 TPs and non-TPs remain present under each ablation. Do not estimate per-variant precision or construct variant-specific annotation samples.

`sv_only` is not a scientific ablation because zero native candidates are guaranteed by the final aggregator. Keep one out-of-population runner fixture asserting zero native candidates and omit the result from the manuscript. Disabling no-op suppression is an artifact engineering sensitivity, not a primary ablation. Disabling external-state modeling remains an artifact sensitivity unless external-state modeling is explicitly claimed as a manuscript contribution.

## Reproducible execution

Use one immutable `linux/amd64` OCI image. Freeze and record its digest, OS packages, Python lock and artifact hashes, Node and Foundry binaries, exact `solc` binaries, architecture, locale, and timezone. The intended primary versions are Python 3.10.20, Slither 0.11.3, crytic-compile 0.3.11, and Foundry v1.5.1; exact project-compatible compiler and JavaScript toolchains are selected only from documented project evidence and the F1 inventory. Dependency acquisition may use the network only before build acceptance. Freeze dependency archives, caches, lockfiles, submodules, compilers, build outputs, and build-information files. Analysis runs are offline.

| Resource | Frozen rule |
| --- | --- |
| CPU | 4 fixed vCPUs |
| Memory | 32 GiB hard limit |
| Swap | disabled |
| Build timeout | 900 seconds per attempt |
| Analysis timeout | 1,800 seconds per run |
| Concurrency | one analysis process per allocation |
| Architecture | `linux/amd64` |
| Timezone | UTC |
| Working path | identical absolute path for every run |
| Source workspace | restored from immutable snapshot before every run |

Every attempted run has a manifest containing run identity, dataset, subject, revision, configuration, seed, repetition, source and build digests, OCI and toolchain digests, compiler digests, command, working path, sanitized environment, resource limits, timing, peak RSS, exit code, terminal status, stdout/stderr digests, raw JSON digest, and canonical JSON digest.

Accept a run only if it exits successfully; avoids timeout, OOM, and context-bound failure; produces parseable complete JSON; matches detector, source, build, compiler, and effective-configuration hashes; satisfies unique-ID and aggregate-count invariants; and contains structurally valid native candidates and witnesses. Freeze raw output before annotation. Validators may be corrected without modifying detector output, with each correction logged and applied to all prior outputs.

Canonical JSON uses UTF-8, lexicographically sorted object keys, compact separators, preserved array order, and one terminal newline. SHA-256 over those bytes is the canonical output digest. Terminal statuses distinguish success, unavailable source/version, build failure or timeout, analysis failure or timeout, OOM, context-bound failure, parse/acceptance failure, and other failure.

## Determinism and performance

Run:

1. B0 seed 0 on the full accepted cohort;
2. B0 seed 1 on every seed-0-successful subject; and
3. one measured B0 invocation for every subject.

Require exact canonical-output equality between seed 0 and seed 1. Report every mismatch with the first divergent canonical path. Timing and other runner metadata are outside detector-output equality. If runtime variability must be quantified, select at most 12 seed-0-successful subjects with the lowest values of `SHA-256("20260811:performance" || subject_id)` and perform three cold repetitions. There is no engineered diversity subset, farthest-point selection, or extra seed-0 determinism regime.

Report only:

```text
completion rate
median runtime
IQR runtime
maximum runtime
median peak RSS
maximum peak RSS
timeout/OOM/context-bound counts
```

## Practical findings

Disclosure-oriented validation occurs only after raw-output freeze and cannot change the precision frame, sample, estimator, or candidate labels. A practical finding must be supported by at least one `TP_MVSI` candidate and receives this compact record:

```text
finding_id
project
revision
source_candidate_ids
semantic_relation
writer_transition
omitted_state
consumer
feasible_sequence
access_model
impact_evidence
prior_public_report
disclosure_status
```

Exploitability, attacker control, impact, severity, novelty, and disclosure are separate from semantic classification. Detailed vendor and novelty workflow may live in a disclosure log. The number of novel findings is never a detector-accuracy metric.

## Adjacent-tool comparison

Run a comparator only when it is executable, accepts the same source revisions, and emits output mappable to the same evaluation unit. State-Checker may support a limited historical comparison if these conditions hold. Do not assign empirical zeros or bespoke partial credit to DivertScan or another incompatible artifact. When direct comparison is infeasible, use a capability comparison in related work and explain the incompatibility.

## Result reporting

The manuscript uses approximately six result tables:

1. Benchmark population and build coverage.
2. Historical classification, recovery, and exact-fix controls.
3. Candidate label counts, primary precision with Wilson interval, and agreement.
4. Core ablations A1, A2, A4, and A5.
5. Determinism and scalability.
6. Error analysis and separately validated findings.

All tables expose raw numerators, denominators, exclusions, and failure counts. No post-result subgroup, alternative denominator, or new success measure may be added without a recorded deviation and a clearly exploratory label.

## Artifact boundary

Operational details that do not define scientific claims belong outside this core protocol:

```text
ARTIFACT_README.md
schemas/
runner_specification.md
```

Those artifacts may contain the full directory tree, complete schemas and manifest fields, fixture descriptions, build-adapter details, disclosure workflow, secondary tags, artifact-only sensitivities, and table-generation commands. They may not silently change an F1 decision.

## Execution and traceability

The execution sequence is:

1. Establish F0 and instantiate F1 artifacts, including benchmark commits, exact builds, scope and exposure fields, C1-C5 guide, minimal oracle, configurations, limits, deterministic selectors, runner, and validator.
2. Complete independent annotation and adjudication of all 116 historical cases before viewing final output; freeze `H` and accepted builds `B`.
3. Apply the no-edit build screen to Web3Bugs and freeze the accepted FULL and CLEAN cohorts.
4. Execute B0, A1, A2, A4, and A5; execute the seed-1 B0 reproducibility pass; validate and freeze raw outputs as F2.
5. Select the equal-probability candidate sample and agreement subsample, annotate, adjudicate, and compute only the frozen measures and six tables.
6. Independently audit every manuscript number against machine-readable artifacts and then establish F3.

Every reported value must be regenerable from immutable artifacts by a frozen script. The independent audit verifies detector hashes, benchmark revisions, population accounting, source scope, exposure assignment, build outcomes, `H`, `B`, `M`, candidate-frame size, sample selection, labels, agreement, ablation counts, determinism comparisons, and table arithmetic.

## Validity and deviation controls

- **Construct validity:** C1-C5 define the target; output-independent historical annotation, conservative candidate precision, and separate practical validation prevent adjacent issues or exploitability judgments from changing detector accuracy.
- **Internal validity:** exact hashes, immutable revisions, no source repair, frozen builds, clean run manifests, original-label preservation, deterministic sampling, and failure-as-miss rules limit researcher degrees of freedom.
- **External validity:** results are bounded to the two frozen Solidity corpora, their accepted builds, and the declared source scope. FULL is primary; CLEAN is the only exposure sensitivity.
- **Conclusion validity:** historical recovery is a census; candidate precision uses one equal-probability sample and one Wilson interval; raw counts and denominators accompany every proportion.

Any deviation records its identifier, date, reason, affected subjects and artifacts, whether semantic output had been inspected, and impact on claims. A deviation never overwrites original evidence. Detector changes invalidate F0 and require rerunning affected evaluation stages. Exploratory analyses after F2 are labeled exploratory and cannot replace frozen primary results.