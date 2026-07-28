# Pre-Evaluation Plan

This document freezes the evaluation protocol. It is meant to summarize how the evaluation will be executed before it begins.

All final evaluation numbers will be regenerated under Slither `0.11.3` and Python `3.10`.

# Note on integrity and rigor

This is a new evaluation. It does not use previous data from earlier experiments, except for one explicitly separated component:
  - MV-Scan recently aided in identifying eight zero-day candidates within Web3Bugs. They remain candidates pending two-annotator validation of validity, novelty, feasibility or exploitability, impact boundary, and disclosure status.

Additionally, all schemas, denominator rules, exclusion reasons, detector configurations, deduplication units, and annotation label sets are frozen before the final rerun. Post-hoc changes must be recorded in a changelog.

## Benchmark Overview

The evaluation is split into two benchmarks where we measure:

**Benchmark 1.** Semantic alignment and strict known-case recovery over independently known ISU findings.
  * The main reported scope is MV-SI. SV-SI, other-SI, non-MV-SI, and excluded outputs are retained with predefined reasons.
  * **Semantic denominator:** known-bug rows adjudicated as MV-SI under C1--C5.
  * **Tool-recovery denominator:** adjudicated MV-SI rows whose source is retrievable, whose reported version or commit is matched, whose project builds under our protocol, and whose analysis completes with parseable MV-Scan output.

**Benchmark 2.** Detector-output precision, ablation behavior, runtime, and diagnostic exclusions over a 61-repo subset of Web3Bugs.
  * The primary precision unit is the structural-signature bucket. Raw detector reports are inputs to deduplication only.
  * **Precision denominator:** scored detector-produced structural-signature buckets.

## Detector Claim

MV-Scan statically infers candidate multi-variable state relations and reports associated transaction context and writer/reader witnesses. *Reference* applies a value-influence sink filter before emitting candidates. The 6 ablations, including one internal baseline, selectively disable our core contributions to assess their impact on precision.

A manual audit determines if the reported reader context corresponds to a behaviorally relevant protocol consumer and if the candidate satisfies the complete MV-SI definition. We claim automated relation-and-witness candidate generation with heuristic sink filtering, followed by manual semantic validation. Naturally, a validation step is crucial in assessing just how far we can get with multi-variable relationships with static approximations.

### Analysis Units

| Unit   | Role    |
| ------ | ------- |
| Raw report | Single emitted detector finding. Preserved as evidence, but not treated as an independent precision unit because multiple raw reports may represent the same structural candidate. These are instead deduplicated into structural-signature buckets. |
| Structural-signature bucket | Primary precision and ablation unit; same repository, detector structural class, canonical relation/entities, transaction-set, operation patterns, and shape tags. Writer/reader witnesses are retained as bounded audit evidence but do not split the primary coarse bucket. |
| Entity-overlap component     | Sensitivity view; findings are connected because they share state variables                  |
| Known-bug oracle row         | Primary recall unit for Benchmark 1. It is a historical bug/finding from TOSEM ISU study that was semantically classified as MV-SI, SV-SI, or ISU-Other |

### Label taxonomy

Oracle semantic labels, used for known-bug rows:

| Label | Meaning |
| ----- | ------- |
| MV-SI | The known bug satisfies C1--C5 for multi-variable state inconsistency |
| SV-SI | The known bug is a single-variable stale/destructive/inconsistent-state issue but does not satisfy MV arity |
| ISU-other | The known bug is an inconsistent-state-update issue but not MV-SI or SV-SI under this definition |
| Other | The known bug is a valid bug or issue but not an inconsistent-state issue under this evaluation definition |
| Excluded/unlabelable | The row lacks enough source/report evidence for semantic classification, is duplicated outside the chosen unit, or is outside the evaluation scope |

Detector-emitted fields, used to construct structural buckets:

| Output label | How it is emitted from the detector itself |
| ------------ | ------------------------------------------ |
| detector_structural_class / pattern | e.g., single_var_cross_tx, multi_var_intra_contract, multi_var_cross_contract |
| reported_state_entities | the variable/group tokens printed after the pattern |
| tx_set | the public/external entrypoints in the candidate transaction context |
| writer_sites | one or more reported write witnesses |
| reader_sites | one or more reported read witnesses |
| op_patterns | stale_read, cross_tx_stale_read, destructive_write, or reentrant variants when available |

Human audit labels for detector-output buckets:

| Label | Meaning | Included in main MV-SI precision? |
| ----- | ------- | --------------------------------- |
| TP-MVSI | Valid MV-SI candidate under the evaluation definition | Yes |
| TP-SVSI | Valid SV-SI candidate under the evaluation definition and 1 variable involved | No, diagnostic only |
| TP-other-ISU | Valid inconsistent-state issue outside MV-SI and SV-SI | No, diagnostic only |
| FP | Not a valid SI finding under the scoped definition | Yes, as FP |
| Excluded | Test/mock/dependency/out-of-scope/unbuildable/duplicate | No, reported separately |

Zero-Day (ZD) status is an orthogonal attribute where TP-MVSI buckets could also be zero-day findings. This status requires separate novelty, exploitability, PoC/sketch, impact-boundary, and disclosure evidence.

Previously identified ZDs are revalidated in a separate evidence table. Final confirmed-zero-day counts are reported only after novelty, exploitability, impact-boundary, and disclosure-status fields are completed.

### Exclusion taxonomies

We specify two separate taxonomies to distinguish provenance/runtime from output scoring.

**Provenance and run-status:** these apply to known-bug rows, repositories, or tool runs before scoring takes place:

| Label | Description |
| ----- | ----------- |
| source_unavailable | Required source artifact could not be retrieved. |
| version_mismatch | Retrieved source does not match the reported vulnerable version, commit, or release context. |
| build_failure | Repository source was retrieved and version-matched, but did not build under the frozen timeout and build protocol. |
| analysis_failure | Repository built, but MV-Scan/Slither failed before producing parseable output. |
| timeout | Build or analysis exceeded the frozen timeout. |
| semantic_unlabelable | The source/report lacks enough evidence for independent semantic classification. |
| evaluable | Source is retrievable, version-matched, buildable, and analyzable under the frozen protocol. |

**Output scoring taxonomy:** these apply to detector-produced rows or buckets after a successful run.

| Label | Description |
| ----- | ----------- |
| scored_mvsi_candidate | Bucket is eligible for main MV-SI precision scoring |
| non_mvsi_scope | Bucket is SV-SI, other-SI, other logical bug, or otherwise outside the main MV-SI reporting scope. It is retained diagnostically but excluded from MV-SI precision |
| duplicate_raw_report | Raw report was merged into an existing structural-signature bucket |
| test_or_mock | Bucket occurs only in test, mock, fixture, harness, generated example, or non-target code |
| dependency_only | Bucket occurs only in dependency/vendor code outside the evaluated target |
| parse_failure | Raw output could not be parsed into the frozen schema |
| non_scored_diagnostic | Output is retained only for diagnostic accounting and is not eligible for precision scoring |

----

## Evaluation Algorithms

We summarize the evaluation process for both benchmarks in "pseudo-code":

### Benchmark 1: Building on TOSEM ISU study

```
For each row in the ISU artifact's 116 rows:
  (a) Record provenance:
    TOSEM Row ID
    Source category
    Reported root cause
    Project/repository
    Expected version/commit
    Affected contract/function
    Source/report URL
  For each annotator:
    (b) (0) semantically label row as MV-SI/SV-SI/ISU-other with the C1..C5 Litmus Test and record:
      (1) state entities: variables/external-state-entities involved
      (2) coupled relation: the invariant/relation between variables
      (3) desynchronization mechanism: how the relation breaks, i.e. stale read, partial update, missing update, and destructive write
      (4) consumer context: where the broken relation is consumed, i.e. accounting, branch, transfer, mint, governance, or liveness
      (5) non-reducibility: whether the complete failure requires the relation among >=2 state entities or can be fully explained as unary ISU
      (6) notes: any additional notes, especially useful for adjudication
For each row adjudicated as MV-SI:
  (a) attempt compilation for <= 15 minutes. If >15 (timeout):
    (i) exclude from tool-recovery denominator. Remains in semantic MV-SI denominator.
Calculate strict recovery over both the semantic MV-SI denominator and the tool-evaluable MV-SI denominator, while clearly identifying the latter as the main tool-recovery denominator.
Use the following matching protocol, where we include a match if both share the same:
  (1) multi-variable relation,
  (2) desynchronization mechanism,
  (3) transaction context,
  (4) write/read witness,
  and (5) the same reported consumer/decision context under manual inspection. (5) passes when the detector-reported reader site is: (a) the known behaviorally relevant consumer; or (b) directly feeds that consumer in the same known-bug trace. MV-Scan does not emit a sink class or certify an explicit sink site. Annotators may inspect surrounding code only to interpret reported writer and reader sites.
To summarize counts:
  Semantic MV-SI count = number of TOSEM rows adjudicated as MV-SI under C1--C5
  Tool-evaluable MV-SI count = number of semantic MV-SI rows whose source is retrievable, version-matched, buildable, and analyzable under the protocol
To summarize recall views:
  Strict tool recall = strict_recovered / N_evaluable_mvsi
  End-to-end lower-bound recall = strict_recovered / N_semantic_mvsi

For each previously identified zero-day from the previous audit, we track the tool trace, its configuration, a PoC/code sketch, a mitigation, and an audit pass to ensure that the finding is new.

For each annotator:
  Pass over each zero-day finding and manually audit the finding's validity via PoC and agreement.
```

> TOSEM semantic labels (e.g., MV-SI or SV-SI) are assigned before both annotators inspect MV-Scan output for the corresponding row. Strict-match annotation is performed only after semantic adjudication freezes the MV-SI denominator.

#### MV-SI Litmus Test (C1--C5)

**C1:** Finding involves >=2 semantically coupled state entities, including storage variables, mapping slots, or external state proxies.
**C2:** Coupled entities participate in a protocol-level invariant/relation rather than merely co-occurring syntactically.
**C3:** Bug mechanism desynchronizes the relation through stale read, partial update, missing coupled update, destructive overwrite, or equivalent state-transition inconsistency.
**C4 Behaviorally relevant consumption:** The desynchronized relation reaches a feasible protocol consumer whose decision or effect can alter accounting, funds, asset movement, pricing, shares, rewards, liquidation, authorization, governance, liveness, or another security-relevant protocol outcome. This fails when no feasible connection exists between the inconsistent relation and a behaviorally relevant downstream consumer. A local/internal computation does not fail C4 due to this alone.
**C5 Multi-variable dependence:** We require an inconsistent relation among >=2 independently meaningful state entities. This fails when the defect can be fully and accurately explained as a unary stale, missing, destructive, or otherwise ISU and the remaining reported entities are incidental context.

**Evidence sufficiency gate:** Evaluated separately, the source report, vulnerable code, PoC, documented execution trace, exploit sketch, or equivalent ground-truth evidence must be sufficient to support semantic classification and feasibility under the stated threat model. Rows without sufficient evidence are labeled `excluded/unlabelable`.


#### Semantic-label decision order

1. If the row fails the evidence-sufficiency gate, label excluded/unlabelable.
2. Else, if the row satisfies all MV-SI C1--C5 conditions, label MV-SI.
3. Else, if the row describes a single-state-entity stale read, stale write, destructive overwrite, or inconsistent-state transition consumed by a behaviorally relevant context, label SV-SI.
4. Else, if the row is an inconsistent-state-update issue but does not satisfy MV-SI or SV-SI, label ISU-other.
5. Else, label other.

#### FN reason taxonomy

For strict recall, false negatives are equally important in determining what MV-Scan missed, but more importantly: why did it miss them? This allows future research to study any static approximations which may help in detecting these subclasses.

| Reason | Description |
| ------ | ----------- |
| `FN0_no_candidate_output` | No reference configuration bucket was produced for the oracle row's repository/function/relation area |
| `FN1_candidate_wrong_relation` | Candidate output exists but does not include the oracle MV relation |
| `FN2_candidate_wrong_desync` | Candidate output touches related state but represents a different desynchronization mechanism |
| `FN3_candidate_wrong_transaction_context` | Candidate output lacks the relevant update/consume functions or equivalent entrypoints |
| `FN4_candidate_wrong_write_read_witness` | Candidate output does not include a corresponding inconsistent update and stale/inconsistent consumer |
| `FN5_candidate_wrong_consumer_context` | Candidate output has relation/witness overlap but not the same behaviorally relevant consumer context |
| `FN6_build_or_analysis_excluded` | Row is semantic MV-SI but not in tool-recovery denominator because source/build/analysis failed |
| `FN7_adjacent_not_strict` | Candidate is in the same protocol area but not the same known bug |

#### Threat-model classes

| Class | Description |
| ----- | ----------- |
| unprivileged | Triggerable by an arbitrary external actor through public/external calls. |
| privileged-but-valid | Triggerable by an owner/admin/governance/keeper role where the known bug report treats the privileged action as a valid defect, configuration hazard, or governance/accounting failure. These are retained but tagged. |
| privileged-trust-assumption-only | Reducible to ordinary trusted-admin behavior without a state-inconsistency defect. These are not MV-SI unless the report/source shows an unsynchronized state relation beyond mere privilege. |
| environmental/external | Requires an external state proxy such as token balance, allowance, oracle value, AMM reserves, timestamp, or cross-contract accounting state. |
| unknown | Feasibility cannot be determined from available evidence. |

#### Final tables

| File | Unit | Schema | Purpose |
| ---- | ---- | ------ | ------- |
| `tosem_oracle_rows.csv`   | TOSEM ISU known-bug | `tosem_id,source_category,reported_root_cause,project_repo,expected_version_commit,affected_contract_function,source_report_url,semantic_class,state_entities,coupled_relation,desync_mechanism,consumer_context,non_reducibility,evidence_sufficiency,adjudication_notes,source_status,version_status,build_status,analysis_status,semantic_mvsi_denominator,tool_recovery_denominator`      | Master table for provenance, adjudicated semantic classification, and denominator flags |
| `tosem_annotations.csv`   | Annotator * TOSEM finding | `tosem_id,annotator,c1_pass,c2_pass,c3_pass,c4_pass,c5_pass,evidence_sufficiency,semantic_class,state_entities,coupled_relation,desync_mechanism,consumer_context,non_reducibility,notes` | Needed for Kappa/agreement and adjudication audit trail |
| `tosem_strict_recall.csv` | MV-SI oracle finding | `tosem_id,baseline_evaluable,candidate_finding_id,same_mv_relation,same_desync_mechanism,same_transaction_context,same_write_read_witness,same_consumer_context_manual,strict_match,fn_reason,notes` | Tracks reference configuration's evaluability and strict-match decision |
| `zero_day_evidence.csv` | Zero-day candidate | `zero_day_id,repo,version_commit,reference_finding_ids,ablation_finding_ids,found_by_reference,found_by_variants,state_entities,coupled_relation,desync_mechanism,consumer_context,poc_or_sketch_status,mitigation,vendor_status,novelty_status,impact_boundary,disclosure_status,validation_status,notes` | Separate validation table for novel findings, including PoC and responsible disclosure |

### Benchmark 2: Web3Bugs ablation audit

```
(1) For each repository in our 61-repository subset:
  (a) mark each repo, author, version/commit, and corresponding audit report ID/date
  (b) attempt compilation for <= 15 minutes. If >15 (timeout):
    (i) exclude from denominator.
  (c) else, create a sheet for the corresponding repo.
(2) For each sheet's corresponding repository:
  For each internal configuration and ablation:
    (a) run inconsistent_state with the correct toggles.
    (b) store all findings row-wise and track finding ID, variant, detector output fields, structural-bucket membership, human audit label, MV-SI precision-denominator membership, zero-day-candidate linkage, and comments.
```

> Note about (2): the canonical artifact will be a long-form CSV where each row is a raw detector report and includes `repo_id` and `variant`.

#### Detector configurations

| Run ID | Name | Purpose | Configuration |
| ------ | ---- | ------- | ------------- |
| Reference (B0) | MV-Scan | Main evaluated detector | Full detector with MV grouping, branch co-use grouping, multi-return grouping, external-state abstraction, mapping precision, and sink-context gate enabled |
| A1 | SV-only | Tests whether MV grouping is necessary | Disable all MultiVarGroup construction and propagation |
| A2 | No branch co-use grouping | Tests predicate-derived MV relations | Disable MV groups derived from branch predicates, require/assert conditions, and conditional co-use |
| A3/IB0 | Predicate-only internal baseline/no multi-return grouping | Tests helper/view-return-derived relation inference and provides the task-matched naive comparator | Use only direct branch/predicate co-use to propose multi-variable relations by disabling multi-return grouping. Keep pseudo insertion/site union, mapping precision, external-state abstraction, user-callable reachability pruning, sink filtering, JSON output, and deduplication identical to Reference. |
| A4 | No external-state abstraction | Tests cross-contract/token/accounting state abstraction | Disable ExternalStateVar, external read/write selector summaries, storage-to-getter aliasing, and ERC-20-style external-state aliases |
| A5 | Mapping-insensitive | Tests mapping-key precision | Collapse mapping slots to the base mapping or otherwise disable key-sensitive slot matching |
| A6 | No late sink filter | Destructive sensitivity variant | Disable only the late sink-context gate after relation inference and stale-pair enumeration. It does not remove earlier read-affects-state filtering in stale-pair generation. |

**Notes:**

**A3/IB0: Predicate-only internal baseline.**

A3 serves as both the `no_multi_return_groups` ablation and as the task-matched internal baseline.

It retains Reference behavior for ICFG construction, user-callable reachability pruning, pseudo-variable insertion and member-site union, mapping-slot precision, external-state abstraction, stale-pair enumeration, late value-influence sink filtering, JSON output, and structural deduplication.

Relation proposal is the changed component: candidate multi-variable relations are proposed only from direct branch/predicate co-use because helper/multi-return relation inference is disabled. It is reported in two roles:

1. As an ablation, it measures the contribution of helper/multi-return relation inference.
2. As an internal baseline, it provides a task-matched direct-predicate co-use comparator.

**Breakdown:**

| Run | Env to set | Internal derived config |
|---|---|---|
| Reference | `MVSCAN_ABLATION=full`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=True`<br>`ENABLE_MULTI_RETURN_GROUPS=True`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True` |
| A1 SV-only | `MVSCAN_ABLATION=sv_only`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=False`<br>`ENABLE_BRANCH_GROUPS=False`<br>`ENABLE_MULTI_RETURN_GROUPS=False`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True` but irrelevant because no MV pseudos are built<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True` |
| A2 No branch co-use grouping | `MVSCAN_ABLATION=no_branch_groups`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=False`<br>`ENABLE_MULTI_RETURN_GROUPS=True`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True` |
| A3/IB0 Predicate-only baseline | `MVSCAN_ABLATION=no_multi_return_groups`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=True`<br>`ENABLE_MULTI_RETURN_GROUPS=False`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True` |
| A4 No external-state abstraction | `MVSCAN_ABLATION=no_external_state`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=True`<br>`ENABLE_MULTI_RETURN_GROUPS=True`<br>`ENABLE_EXTERNAL_STATE=False`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True` |
| A5 Mapping-insensitive | `MVSCAN_ABLATION=mapping_insensitive`<br>`SINK_TEST=value`<br>`DIVERGENCE_BUDGET=1000` | `ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=True`<br>`ENABLE_MULTI_RETURN_GROUPS=True`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=base_collapsed`<br>`REQUIRE_SAME_SLOT_KEY=False` |
| A6 No late sink filter | `MVSCAN_ABLATION=full`<br>`SINK_TEST=none` or unset<br>`DIVERGENCE_BUDGET=1000` | Same as Reference for relation inference:<br>`ENABLE_MULTIVAR_GROUPS=True`<br>`ENABLE_BRANCH_GROUPS=True`<br>`ENABLE_MULTI_RETURN_GROUPS=True`<br>`ENABLE_EXTERNAL_STATE=True`<br>`ENABLE_PSEUDO_SITE_UNION=True`<br>`MAPPING_MODE=precise`<br>`REQUIRE_SAME_SLOT_KEY=True`<br>Late sink filter disabled because `hits_sink()` returns `True` unless `SINK_TEST` is exactly `value` or `samevar`. |

#### Frozen runtime flags

In addition to the variant-specific settings above, all final runs use these frozen runtime flags:

| Flag | Frozen value | Notes |
|---|---:|---|
| `ISD_JSON_OUT` | required, run-specific path | Every detector run must emit JSON. The output path is recorded in `benchmark*_runs.csv`. |
| `DIVERGENCE_BUDGET` | `1000` | Applies to all sink-gated variants. |
| `INIT_ONLY_FILTER` | `1` | Filters creation-phase / initializer-only state artifacts. |
| `ADMIN_WRITES_BENIGN` | `1` | Drops admin-writer/user-reader pairs treated as benign under the detector’s scoped threat model. |
| `USER_CALLABLE_INCLUDE_ROLE_GATED` | `0` | Role-gated/admin-only public functions are excluded from ordinary user-callable reachability unless explicitly overridden. |
| `USER_CALLABLE_ALWAYS` | empty string | No function is force-included unless a per-repository override is frozen before evaluation. |
| `USER_CALLABLE_DENY` | empty string | No function is force-denied unless a per-repository override is frozen before evaluation. |
| `COARSE_DEDUP` | `1` | The primary precision unit is the intentionally coarse structural bucket, not every distinct witness pair. |
| `ATOMIC_GROUP` | empty string | No entrypoints are manually merged unless a per-repository override is frozen before evaluation. |
| `MERGE_OVERLOADS` | `0` | Overloaded functions remain distinct by default. |
| `PROMOTE_MAPPING_BASE` | `0` | Mapping bases are not promoted into branch groups unless the relevant ablation explicitly changes mapping behavior. |
| `NOOP_WRITE_FILTER` | `1` | Self-copy/no-op writes are filtered. |
| `REQUIRE_SAME_SLOT_KEY` | `1` env setting | Effective only when `MAPPING_MODE=precise`; it is effectively false only for `mapping_insensitive`, which collapses mapping slots. A3/IB0 retains precise mapping and same-slot-key matching. |

A3/IB0 retains precise mapping behavior and same-slot-key matching.

Any non-empty per-repository override for these frozen flags must be noted in `benchmark*_runs.csv` before annotation and should include the repository ID, variant, flag name, value, and reason. Overrides added after seeing detector outputs are prohibited and must be recorded only as post-freeze deviations in the changelog.

#### Separation of result populations

1. **Reference/B0 precision** Only scored Reference structural-signature buckets enter the headline precision denominator. Ablation-only findings are not included.

2. **Ablation behavior** Reference and A1--A6 are compared under the same primary deduplication unit. These results explain component effects and are not pooled into Reference's precision.

3. **Zero-day evidence** ZD candidates are reported in a separate evidence table. Their counts are not used as a precision numerator/denominator.


#### MV-SI precision denominator

- A structural-signature bucket enters the main MV-SI precision denominator if:
  1. it is non-excluded under the frozen structural exclusion rules; and
  2. its detector-emitted structural class is one of: `multi_var_intra_contract`, `multi_var_cross_contract`.
- The numerator is the subset of those denominator buckets whose human audit label is TP-MVSI. `MVSI_precision = TP-MVSI among detector-MV-scope buckets / all scored detector-MV-scope buckets`.
- If a detector-MV-scope bucket is later audited as TP-SVSI, TP-other-ISU, or FP, it remains in the MV-SI precision denominator and is not counted in the TP-MVSI numerator.
- If a detector-SV-scope bucket is later audited as a valid issue, it is retained diagnostically but does not enter the main MV-SI precision denominator.

#### How do we construct structural signatures?

Before setting the formula, we define a few terms:

| Term | Description |
| ---- | ----------- |
| `canonical_state_entities` | State variables are normalized by contract, variable name, and storage slot when available. Mapping slots are normalized by base mapping plus canonical key expression when precise mode is enabled. In mapping-insensitive mode, mapping slots normalize to the base mapping. External state proxies are normalized by callee address/domain when available plus selector. |
| `normalized_tx_set` | Sorted set of normalized public/external entrypoint signatures |
| `normalized_writer_shape`/`normalized_reader_shape` | Contract and function signature and source file and normalized line or source span when available. If source location is missing, use a report-specific missing-location token to avoid merging unrelated reports. |
| Missing fields | These must be encoded as report-specific tokens, not shared `NULL` values, unless the field is intentionally absent by design |

We distinguish two identifiers:

| Identifier | Meaning |
| ---------- | ------- |
| `global_structural_signature` | Variant-independent signature used for manual labeling and cross-variant projection. |
| `variant_bucket_id` | Variant-specific bucket ID used for per-variant precision/runtime summaries. It is computed from the variant plus the global structural signature. |

Manual labels are assigned to `global_structural_signature` and projected to all matching `variant_bucket_id` rows.

We use the following hash formulas:

```python
global_structural_signature = hash(
  repo_id,
  detector_structural_class,
  variant_independent_canonical_relation_key,
  sorted(canonical_state_entities),
  sorted(normalized_tx_set),
  sorted(op_patterns),
  sorted(shape_tags)
)

variant_bucket_id = hash(
  variant,
  global_structural_signature
)
```

#### Bucket-coherence diagnostics

`global_structural_signature` remains the primary Benchmark 2 precision unit. It is not changed after manual labels or precision outcomes are inspected. Add `raw_report_count` to every structural bucket. For every variant, report:

- number and proportion of singleton buckets;
- median raw reports per bucket;
- 90th-percentile bucket size;
- 95th-percentile bucket size;
- maximum bucket size; and
- identities and sizes of the 20 largest buckets.

After bucketing, manually inspect the 20 largest coarse buckets; and every coarse bucket with `raw_report_count >= 10`. This inspection checks whether coarse buckets mix materially different writer contexts, reader contexts, desynchronization mechanisms, or manually inferred consumer contexts. The inspection does not change the primary coarse signature. For those buckets, compute a secondary witness-sensitive subdivision:

```python
witness_sensitive_signature = hash(
  global_structural_signature,
  sorted(normalized_writer_shape),
  sorted(normalized_reader_shape)
)
```

Report whether the witness-sensitive subdivision materially changes bucket count or precision. Coarse-bucket precision remains the headline result.

Any future proposal to replace the primary coarse signature must be made before final annotation, applied uniformly to every variant, and recorded in the protocol changelog. It may not be adopted post hoc in response to observed precision results.

**Output structure note**: Console output headers usually look like this: ```[multi_var_cross_contract] mapMemberSynth_lastTime, {mapMemberSynth_lastTime}```. This produces compact group tokens that may be difficult to read. The canonical source will therefore be the JSON fields that accompany every finding. Pretty-printed variable/group tokens may be truncated, duplicated, or less precise than the JSON `vars`, `shape_by_var`, writer, and reader fields.

#### Final tables

* MV-SI precision per variant: TP-MVSI detector-MV-scope buckets / all non-excluded scored detector-MV-scope buckets.
* Runtime (s) summary per variant, aggregated across repositories.
* An overview table such as:

| Variant | Repos run | Raw reports | Structural buckets | TP buckets | FP buckets | Precision | Runtime |
| ------- | --------: | ----------: | -----------------: | ---------: | ---------: | --------: | ------: |
| Reference |    61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A1    |        61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A2    |        61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A3/IB0 |       61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A4    |        61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A5    |        61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |
| A6    |        61   |     XX      |        XX          |     XX     |     XX     |     XX    |   XX    |

The exact file schema for Benchmark 2 tables is as follows:

| Filename | Schema |
| -------- | ------ |
| `benchmark2_runs.csv` | `run_id,repo_id,variant,slither_version,command,env_json,build_status,analysis_status,build_seconds,analysis_seconds,timeout_seconds,output_json_path,stderr_log_path,notes` |
| `benchmark2_raw_reports.csv` | `raw_report_id,run_id,repo_id,variant,detector_structural_class,detector_scope,vars_json,expanded_canonical_entities_json,tx_set_json,writers_json,readers_json,op_patterns_json,shape_json,shape_by_var_json,raw_text,parse_status,raw_report_status,structural_exclusion_reason,notes` |
| `benchmark2_structural_buckets.csv` | `variant_bucket_id,global_structural_signature,witness_sensitive_signature,repo_id,variant,detector_structural_class,detector_scope,canonical_relation_key,canonical_state_entities,tx_set,op_patterns,shape_tags,writer_witnesses_json,reader_witnesses_json,raw_report_ids,raw_report_count,human_audit_label,zero_day_status,bucket_scoring_status,structural_exclusion_reason,coherence_audit_status,heterogeneity_notes,label_notes` |
| `benchmark2_ablation_summary.csv` | `variant,repos_attempted,repos_buildable,repos_analyzed,raw_reports,structural_buckets,singleton_buckets,median_bucket_size,p90_bucket_size,p95_bucket_size,max_bucket_size,tp_mvsi_buckets,fp_buckets,diagnostic_svsi_buckets,diagnostic_other_isu_buckets,excluded_buckets,precision,median_runtime_seconds,total_runtime_seconds` |
| `benchmark2_bucket_diagnostics.csv` | `global_structural_signature,variant,raw_report_count,is_top20_bucket,is_size_ge_10,witness_sensitive_subbucket_count,mixed_writer_context,mixed_reader_context,mixed_desync_context,mixed_consumer_context,coherence_assessment,notes` |

#### Labeling structural-signature buckets

Raw reports are not independently labeled since they are deduplication inputs. Manual labels get assigned once to unique global structural signatures and then projected to all raw reports/variant rows that map to that same signature.

The audit is performed by one primary auditor. A second auditor independently labels a frozen stratified sample of structural-signature buckets to estimate annotation reliability. Disagreements are adjudicated and used to refine the labeling guide while keeping the bucket construction role frozen.

A global structural signature is derived from repository, detector structural class, canonical relation/entities, transaction set, operation patterns, and shape tags. Writer/reader witnesses are retained as bounded evidence fields and may be inspected during audit, but they do not split Benchmark 2 precision buckets. Each global structural signature receives one manual label even if present in multiple variants.

Additionally, a second auditor does an annotation pass over a stratified reference configuration sample to demonstrate rigor.

## Annotation Protocol

Depending on what audit is being done, there are different requirements set that show rigor in our evaluation of MV-Scan. Some of these apply pre-evaluation and some apply after.

| Audit target | Annotation plan | Agreement unit | Label set | Agreement metric | Finalization / sampling notes |
|---|---|---|---|---|---|
| TOSEM semantic labels | 2 annotators independently label qualified TOSEM rows before viewing the corresponding MV-Scan output. Each annotator records the final semantic class and separate binary judgments for C4 and C5. | Semantically labelable TOSEM row | Final class: MV-SI; SV-SI; ISU-other; other; excluded/unlabelable. Additional fields: `c4_pass` = yes/no and `c5_pass` = yes/no. | For the final semantic class, report unweighted Cohen’s κ, raw agreement, and the full class-confusion matrix. For C4 and C5 separately, report binary raw agreement and a 2x2 confusion matrix; also report Cohen’s κ when both yes and no occur in the combined annotations, otherwise report κ as undefined due to a degenerate label distribution. | All annotations are frozen before adjudication. Agreement statistics use the original independent labels. Disagreements in final class, C4, or C5 are then adjudicated, and the adjudicated values become the final oracle labels. |
| Strict B0 match decisions | 2 annotators or adjudicated review for MV-SI denominator rows | Adjudicated MV-SI row with at least one candidate B0 finding or explicit no-candidate status | strict_match_yes; strict_match_no | Cohen’s κ plus raw agreement if independently labeled by both annotators; otherwise reported as adjudicated review | Used for strict B0 denominator/match reporting |
| Benchmark 2 bucket precision | 1 primary annotator labels unique global signatures; second annotator labels a stratified sample for κ | Structural-signature bucket | TP-MVSI; TP-SVSI; TP-other-ISU; FP; excluded | Cohen’s κ plus raw agreement on the stratified sample | Sample stratified by variant, pattern class, repository, and bucket size |
| Zero-days | 2-annotator validation/adjudication | Zero-day candidate | valid_confirmed; valid_unconfirmed; invalid; duplicate_known_issue | Adjudicated agreement; κ reported only if both annotators independently label the full candidate set | Final validity determined through adjudication |

## Protocol changelog

Any change after the freeze is recorded in the following format: `change_id,date,field_changed,old_value,new_value,reason,approved_by`

## Frozen toolchain

To elaborate on the exact tools used for this study:

| Tool | Version |
| ---- | ------- |
| Python | 3.10 |
| Slither | 0.11.3 |
| crytic-compile | 0.3.11 |
| solc/solc-select | per-repository compiler version recorded in benchmark*_runs.csv |
| Node | v20.20.2 |
| npm/yarn/pnpm | npm 10.8.2; yarn 1.22.22; pnpm 11.7.0; package manager used recorded per repo in benchmark*_runs.csv |
| Foundry/Forge | forge 1.5.1-stable, commit b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2 |
| Hardhat | repo-pinned version recorded per repo in benchmark*_runs.csv |
| Timeouts | 15 minutes build, 15 minutes analysis unless otherwise specified |
| Hardware | 4 x 24-core Intel Xeon Platinum 8360H server, 96 physical cores/192 threads, 512 GiB RAM, SSD storage |

## Dependency repair policy

**Allowed**: installing declared dependencies, selecting the declared Solidity compiler, running repo-documented build commands, applying non-semantic build-file repairs recorded in patch logs.

**Not allowed**: editing Solidity source semantics, editing vulnerable contract logic, changing reported bug-relevant source, or applying patches that alter the analyzed program behavior.