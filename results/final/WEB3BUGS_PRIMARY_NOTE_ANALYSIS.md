# Web3Bugs primary audit: note-level analysis

## Scope and method

This analysis covers all 1,270 completed rows in `web3bugs_primary_audited_ALL_1270_completed.csv`. Blank labels on completed all-pass rows are interpreted as `TP_MVSI`, following the review guide. The analysis uses the coded fields as authoritative and treats the prose notes as explanatory evidence. Mechanism-family counts below are conservative note-based coding, not a claim that structural buckets have been formally consolidated into distinct bugs.

The sheet is internally consistent:

- all 1,270 rows are complete and have evidence notes;
- all 301 blank-label rows pass C1–C5 and therefore derive `TP_MVSI`;
- all 969 `NONBUG` rows have exactly one failed criterion and one permitted primary cause;
- all 31 `protocol_relation_supported=NO` rows are exactly the 31 C2 failures.

## 1. Where candidates actually fail

| First failed criterion | Rows | Share of all rows | Share of NONBUG rows |
|---|---:|---:|---:|
| C2: real relationship | 31 | 2.4% | 3.2% |
| C3: desynchronizing partial transition | 937 | 73.8% | 96.7% |
| C4: stale/omitted value behaviorally consumed | 1 | 0.1% | 0.1% |
| C1 or C5 | 0 | 0.0% | 0.0% |

This is the most important result in the notes. MV-Scan almost always finds multiple persistent values, and 1,239/1,270 relations (97.6%) were judged protocol-supported. Candidates overwhelmingly fail because the alleged writer does not create a committed partial transition that survives to a consumer.

The false-positive problem is therefore not primarily arbitrary relation discovery. It is deciding whether two related values must co-evolve on this operation, whether reconciliation happens before observation, and whether the writer and reader can touch the same state in a feasible order.

## 2. NONBUG mechanisms

| Primary cause | Count | Share of NONBUG rows | What the notes repeatedly say |
|---|---:|---:|---|
| No desynchronizing partial transition | 522 | 53.9% | One member is policy/configuration, state is intentionally lazy, values are independent inputs, or the nominated write is itself the correct pending/checkpoint transition. |
| Reconciliation precedes consumption | 291 | 30.0% | The operation repairs all dependent state before return or before any relevant consumer. |
| Analysis abstraction error | 104 | 10.7% | A read is modeled as a write, a block is split across adjacent writes, or aggregate struct/array identity conflates unrelated fields. |
| Unsupported or overbroad relation | 31 | 3.2% | Values co-occur in a calculation but have no synchronization invariant. |
| Incompatible context, key, or ordering | 20 | 2.1% | Writer and reader use different keys, mutually exclusive branches, or lifecycle states that cannot occur in the required order. |
| Omitted state not behaviorally consumed | 1 | 0.1% | A stale historical slot exists but is never read again. |

The first two causes account for 813/969 nonbugs (83.9%). That gives a concrete optimization target: operation summaries should encode atomic repair, checkpoint-before-change behavior, lifecycle guards, and feasible same-key flow.

### Repeated subpatterns

- **Fixed policy mistaken for mirrored state.** At least 231 notes explicitly discuss fixed/configured parameters, thresholds, limits, or policy values. Examples include `overdueBlocks`, `marketCloseLimit`, `minActiveBalance`, and fee/risk settings. A changing balance or record does not imply the governing limit must change.
- **Independent inputs mistaken for an invariant.** At least 160 notes explicitly say values are independent or need not co-update. Downstream co-consumption is not enough to establish a state relationship.
- **Immediate repair.** At least 183 reconciliation notes explicitly describe immediate or same-operation repair before a consumer.
- **Swap-and-pop/index repair.** At least 62 reconciliation notes describe clearing the removed index and repairing the moved record. This is a particularly repetitive RealityCards pattern.
- **Read modeled as write.** At least 52 abstraction-error notes identify read-only/view logic as a persistent writer, especially Paladin `userLocks` and Nested shareholder reads.
- **Aggregate-field conflation.** At least 17 abstraction-error notes identify whole-struct aggregation, especially RealityCards `Card` fields, as combining unrelated state members.

These are lower bounds based on explicit wording, not exhaustive semantic recoding.

## 3. True-positive mechanism families

The 301 TP rows are not 301 distinct bugs. The notes repeatedly describe different writer nodes, entrypoints, inverse/corrective transitions, and relation cuts for the same semantic defect. Three projects alone contribute 151 TP buckets (50.2%); five contribute 182 (60.5%); the ten largest contributors account for 245 (81.4%).

The largest recurring families identified directly from the notes are:

| Mechanism family | TP buckets | Recurring semantic core |
|---|---:|---|
| Union indexed-debt/accrual | 36 | Per-account debt snapshots are consumed against an old global `borrowIndex` before accrual advances the market checkpoint. |
| Paladin same-block history | 33 | Multiple `UserLock` checkpoints can share `fromBlock`, making historical queries ambiguous or manipulable. |
| Paladin emission rate/checkpoint | 25 | A new emission rate is applied to elapsed time since an old reward checkpoint, retroactively repricing the interval. |
| Float launch-parameter/snapshot | 22 | Mutable launch parameters are interpreted against an unchanged initial timestamp/snapshot. |
| Backd boost-configuration epoch | 17 | Reinitialization changes global boost parameters while per-user boost checkpoints persist from the old configuration. |
| Unlock stale transfer authorization | 15 | Ownership changes while manager/approval authority survives and can be consumed by the prior party. |
| Sherlock insolvent-premium accrual | 13 | Insolvency repair advances/zeros balance checkpoints while a positive premium rate remains live and continues erroneous accrual. |
| Trident mutable fee baseline | 13 | `barFee` changes without rebasing `kLast`/`dLast`, so the next mint applies the new fee to growth accumulated under the old baseline. |
| Float supply/curve checkpoints | 12 | Issuance or curve parameters change without checkpointing accumulated supply/reward state. |
| Float next-price liveness | 10 | A pending user index cannot mature when the global market index fails to advance. |
| Float pending shifts versus stake | 10 | Repeated pending shifts are individually checked against current stake without reserving prior pending amounts. |
| Trident reserve/supply unsafe mint | 10 | LP supply can increase without commensurate reserves due to overflow, truncation, or unsafe balance checks. |

The dominant positive pattern is **mutable regime plus stale checkpoint**. Rates, APRs, fee fractions, launch parameters, boost settings, issuance parameters, and premium rates are changed while time, cumulative value, per-user factor, or growth baseline remains from the prior regime. A later consumer bridges the two epochs and applies the new regime retroactively or uses an old checkpoint under new rules.

The second dominant pattern is **index/history/lifecycle state that becomes unconsumable or ambiguously consumable**: duplicate block-number checkpoints, advanced claim cursors, pending indices that never mature, stale orderbook indices, and epoch ranges containing empty periods.

The third is **local versus aggregate accounting divergence**: per-position debt versus global debt, balances versus total supply, reserves versus LP supply, or active balance versus premium-rate state.

## 4. Project concentration and detector behavior

| Project (subject) | Audited | TP | Precision within audited subject |
|---|---:|---:|---:|
| Paladin (105) | 138 | 58 | 42.0% |
| Float Capital (22) | 100 | 54 | 54.0% |
| Union (45) | 126 | 39 | 31.0% |
| Reality Cards (26) | 275 | 16 | 5.8% |
| Unlock (54) | 20 | 15 | 75.0% |
| Backd April (112) | 32 | 14 | 43.8% |
| Sherlock (76) | 102 | 13 | 12.7% |
| Sushi Trident clone (35) | 41 | 13 | 31.7% |
| Backd May (131) | 23 | 12 | 52.2% |
| Sushi Trident (29) | 27 | 11 | 40.7% |

Candidate generation is highly project- and representation-dependent. RealityCards alone contributes 259/969 nonbugs (26.7%), driven heavily by list/index cleanup, work-bound policy variables, aggregate `Card` fields, and different-key contexts. Paladin contributes 39/104 abstraction errors (37.5%), largely because read-only `userLocks` logic is modeled as a writer. These concentrations mean a few modeling repairs could remove large repeated false-positive families.

The high within-subject yield for Unlock, Float, and the two Backd snapshots shows that the detector can repeatedly land on genuine state-machine surfaces once a contract exposes the relevant relation shape. Conversely, several projects have zero TP buckets, so average precision hides substantial heterogeneity.

## 5. What the notes reveal about granularity

The notes use the word `granularity` in 120/301 TP rows (39.9%). Twenty-nine TP notes explicitly accept an overbroad, extra, or companion relation member. Common formulations include:

- corrective-, inverse-, consumer-, or adjacent-transition granularity;
- a writer localized to a neighboring node while the packet still carries the vulnerable origin;
- a broader aggregate relation containing the essential defect core plus irrelevant members;
- different entrypoints or helper paths reaching the same underlying defect.

This is scientifically important. It shows that MV-Scan often recovers the **semantic defect surface** without isolating the minimal invariant or exact faulting write. That is valuable for a may-analysis, but the paper must not imply that every TP is a precise localization. Precision here means the structural bucket contains a defensible C1–C5 MV-SI witness, sometimes at broader-than-minimal granularity.

Representative cases include Paladin history buckets with ERC20 balance as an extra member, Trident unsafe-mint buckets localized at an adjacent burn/swap writer, and Union indexed-debt buckets serialized at the corrective accrual checkpoint.

## 6. Recovery, novelty language, and what cannot yet be claimed

The TP notes explicitly use recovery language in 171 rows (56.8%) and cite a published H/M/L report identifier in 218 rows (72.4%). They use `new` or `novel` in 98 rows, but 33 of those also use recovery language, 31 cite a published issue identifier, and 12 explicitly say duplicate. Only 49 TP notes use new/novel language without either recovery wording or a published issue identifier.

Therefore:

- `301 TP buckets` is a candidate-level result;
- `98 notes saying new/novel` is not a validated-new-finding count;
- even `49 apparently new surfaces` is only an upper-bound triage pool;
- distinct findings require consolidation across entrypoints, structural cuts, snapshots, and repeated family members, followed by exploitability/novelty validation.

The notes already contain strong consolidation hints (`same family`, `duplicate`, `broader granularity`, cross-referenced review IDs). Those hints should seed the next manual template rather than be treated as final disclosure decisions.

## 7. Ablation-facing patterns

Within each 400-row configuration sample, the primary labels and nonbug causes are:

| Config | TP | No partial transition | Reconciled first | Abstraction error | Unsupported relation | Context/key/order | No consumption |
|---|---:|---:|---:|---:|---:|---:|---:|
| B0 | 82 | 184 | 79 | 36 | 9 | 9 | 1 |
| A1 | 114 | 140 | 103 | 36 | 3 | 4 | 0 |
| A2 | 73 | 191 | 79 | 36 | 12 | 8 | 1 |
| A4 | 94 | 195 | 57 | 31 | 13 | 10 | 0 |
| A5 | 77 | 190 | 86 | 32 | 10 | 5 | 0 |

A1's higher precision is driven mainly by fewer `no_desynchronizing_partial_transition` rows, not fewer abstraction errors. A4 has fewer reconcile-before-consumption rows but slightly more unsupported/context failures. These are descriptive comparisons over different equal-probability configuration samples; they do not prove a paired causal effect for individual buckets.

## 8. Representative note-grounded examples

- **Retroactive rate application:** W3B-0050 and W3B-1265 describe Paladin updating `currentDropPerSecond` before applying it across time since `lastRewardUpdate`.
- **Mutable configuration against stale checkpoint:** W3B-0012 describes Float launch parameters interpreted against the original snapshot timestamp; W3B-0289 describes Trident `barFee` applied against an old `kLast`.
- **Stuck progress index:** W3B-0018 describes a pending next-price cursor that never matures when the global index does not advance.
- **Stale authorization after ownership transfer:** W3B-0177 and W3B-0192 describe Unlock ownership changes leaving manager/approval authority live.
- **Aggregate accounting divergence:** W3B-1103 describes Union adding principal plus origination fee after checking only principal against debt-ceiling headroom.
- **Correct negative due to atomic repair:** W3B-0078 describes swap-and-pop followed immediately by removal-index clearing and moved-record reindexing.
- **Correct negative due to fixed policy:** W3B-0002 distinguishes a fixed delinquency threshold from borrower debt state.
- **Abstraction error:** W3B-0019 treats a read-only Paladin `userLocks.length` condition as a writer; W3B-1270 conflates unrelated fields of an aggregate RealityCards `Card`.
- **Infeasible context:** W3B-0235 shows the emitted Paladin first-lock branch cannot occur from the nominated `increaseLockDuration` entrypoint.

## 9. Paper-facing conclusions

1. **Relation inference is not the main precision bottleneck.** A supported relation was found in 97.6% of rows; 96.7% of nonbugs fail at C3.
2. **Feasibility and reconciliation are the next technical frontier.** The notes repeatedly demand atomic operation summaries, checkpoint semantics, lifecycle guards, and same-key flow.
3. **The detector is effective at defect-family surfacing but often redundant.** A few recurring mechanisms generate many structural buckets across writers and entrypoints.
4. **The strongest positive mechanism is cross-epoch accounting.** Mutable rates/configuration combined with stale temporal or cumulative checkpoints recur across unrelated protocols.
5. **Localization is often broader than the minimal bug.** This is acceptable for candidate generation but must be stated explicitly.
6. **The review data already points to high-leverage engineering fixes.** RealityCards aggregate/list modeling and Paladin read-as-write behavior account for large repeated false-positive clusters.
7. **Novelty is unresolved.** Candidate-level `new/novel` wording must not be converted into a validated-finding count without consolidation and external validation.
