# Reviewing the 116 published ISU findings

As an annotator, decide which of 116 bugs from the 2026 ISU study meet MV-Scan's definition of a multi-variable state inconsistency (MV-SI).

Work only from the finding cards linked in your packet. The cards are helpful summaries of the published report facts and, when available, pinned source excerpts.

## Completing a row

1. Open the card in `known_finding`.
2. Read the root cause, documented consequence, fix, and any useful source excerpt.
3. Evaluate C1 through C5 in order. Some of the columns may be structurally true and you can quietly skip those columns without labeling them.
4. Enter `N` only when a criterion fails. Enter `U` only when the supplied evidence cannot establish that criterion.
5. If any criterion is `N` or `U`, write one short, specific explanation in `annotation_notes`. This helps during adjudication.
7. After evaluating all five criteria that define MV-SI, enter `Y` in `review_complete` and move to the next row.

The `review_complete` mark is required even when C1-C5 are all blank because it indicates that a row passes as `MV-SI`. Without it, an untouched row would look identical to a reviewed, passing row.

Verdicts are derived automatically:

- Any `N` means `NON_MVSI`.
- Otherwise, any `U` means `INSUFFICIENT_EVIDENCE`.
- Otherwise, the finding is `MV_SI`.

## C1-C5

- **C1 -- Multiple persistent entities:** At least two persistent-state entities participate in the defect. Different names for one logical location do not count.
- **C2 -- Protocol relation:** Independent evidence shows that the entities have a real semantic relationship. Proximity, similar names, or use in the same function is not enough.
- **C3 -- Desynchronizing partial transition:** A feasible operation changes a nonempty proper subset of the relationship and leaves at least one related entity inconsistent.
- **C4 -- Omitted-member consumption:** Before reconciliation, an omitted or stale entity is read from persistent state and affects control flow, a storage write, or an external effect.
- **C5 -- Multi-variable essentiality:** The defect essentially depends on the relationship between at least two persistent entities. A unary stale-variable bug fails C5 even if other state appears nearby.

Evaluate the documented defect, not whether it is exploitable by an unprivileged attacker and not how severe it is.

## Notes for exceptions

A note is needed only when you enter `N` or `U`. State which criterion is affected and why. For example:

- `C1 N: only one persistent value participates`
- `C2 N: the other state is incidental; no relationship is shown`
- `C4 N: reconciliation necessarily occurs before the stale value is used`
- `C3 U: the supplied evidence does not show the operation that creates the inconsistent state`

If more than one criterion is `N` or `U`, cover each one briefly in the same note cell.

## What you do not record in this stage

You need enough evidence to judge C3 and C4, but you do not have to transcribe the exact writer, written members, omitted members, persistent read, sink, ordering, or reconciliation point.

After both reviewers finish and disagreements are adjudicated, the research team creates that separate strict-match record only for findings classified as `MV_SI`. That later task compares the historical defect with B0 detector candidates. Keeping it separate makes this review faster and keeps it detector-blind.

## When evidence is limited

Use `U` only when the card cannot establish a criterion. Say exactly what is missing. Do not search the administrative tree or MV-Scan output for additional clues.
