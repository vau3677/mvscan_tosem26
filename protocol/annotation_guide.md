# Reviewing the 116 published ISU findings

## What this review is for

You are deciding which of 116 already-published bugs meet MV-Scan's definition of a multi-variable state inconsistency (MV-SI). You are not evaluating MV-Scan, matching detector output, or re-auditing the whole project.

Work only from the finding card linked in your assigned CSV. The card contains published report facts and, when available, pinned source excerpts. Do not inspect detector output, another reviewer's sheet, or administrative files.

## Complete one row

1. Open the card in `known_finding`.
2. Read the root cause, documented consequence, fix, and any useful source excerpt.
3. Evaluate C1 through C5 in order.
4. Leave a criterion blank when it passes. You may enter `Y`, but it is unnecessary.
5. Enter `N` only when a criterion fails. Enter `U` only when the supplied evidence cannot establish that criterion.
6. If any criterion is `N` or `U`, write one short, specific explanation in `annotation_notes`.
7. After evaluating all five criteria, enter `Y` in `review_complete` and move to the next row.

The `review_complete` mark is required even when C1-C5 are all blank. Without it, an untouched row would look identical to a reviewed all-pass row.

Do not enter an overall verdict. It is derived automatically:

- Any `N` means `NON_MVSI`.
- Otherwise, any `U` means `INSUFFICIENT_EVIDENCE`.
- Otherwise, the finding is `MV_SI`.

## C1-C5

- **C1: Multiple persistent entities:** `>=2` persistent-state variables participate in the defect. "Variables" may be scalar state variables, precise mapping or array locations, semantically distinct slots of one base mapping, or state-backed values obtained through external view calls when independent evidence shows that they represent persistent protocol state. Multiple names for one logical location do not satisfy C1.
- **C2: Protocol relation:** Independent evidence must support a semantic relationship among the participating variables. Acceptable evidence includes protocol logic, documentation, tests, reports, economics, a proof of concept, a concrete trace, comments corroborated by behavior, or the documented rationale for a fix. Detector co-influence, a shared branch or return, naming similarity, and proximity are insufficient by themselves. An emitted relation may contain a semantic core of `>=2` variables; additional emitted members are recorded as over-approximation.
- **C3: Desynchronizing partial transition:** A feasible operation changes a nonempty proper subset of the semantic relation, leaves `>=1` related entity unreconciled, and makes the relationship stale, violated, or otherwise inconsistent. It fails C3 when the omitted entity is independent, the intermediate state is permitted, reconciliation necessarily precedes relevant use, the write is a semantic no-op, or writer and reader cannot occur in one protocol execution. Feasibility requires at least one valid state, call sequence, actor set, and required external conditions, not an unprivileged attacker.
- **C4: Omitted-member consumption before reconciliation:** `>=1` omitted relation member is read from persistent state after the desynchronizing transition and before reconciliation, and that read reaches a behaviorally relevant modeled `control`, `storage_write`, or `external_effect` sink. Record the omitted entity, exact read, consumer, sink, ordering, reconciliation point, transaction relationship, and behavioral relevance. Logging, debugging, dead computation, and outcome-insensitive uses fail C4.
- **C5: Multi-variable essentiality:** The defect must depend essentially on the relationship between `>=2` persistent-state variables. A unary stale-variable defect fails C5 even when additional emitted entities are incidental.

Evaluate the documented defect, not whether it is exploitable by an unprivileged attacker and not how severe it is.

## Notes for exceptions

A note is needed only when you enter `N` or `U`. State which criterion is affected and why. For example:

- `C1 N: only one persistent value participates`
- `C2 N: the other state is incidental; no relationship is shown`
- `C4 N: reconciliation necessarily occurs before the stale value is used`
- `C3 U: the supplied evidence does not show the operation that creates the inconsistent state`

If more than one criterion is `N` or `U`, cover each one briefly in the same notes cell.

## What you do not record in this stage

You need enough evidence to judge C3 and C4, but you do not have to transcribe the exact writer, written members, omitted members, persistent read, sink, ordering, or reconciliation point.

After both reviewers finish and disagreements are adjudicated, the research team creates that separate strict-match record only for findings classified as `MV_SI`. That later task compares the historical defect with B0 detector candidates. Keeping it separate makes this review faster and keeps it detector-blind.

## When evidence is limited

Use `U` only when the card cannot establish a criterion. Say exactly what is missing. Do not search the administrative tree or MV-Scan output for additional clues.
