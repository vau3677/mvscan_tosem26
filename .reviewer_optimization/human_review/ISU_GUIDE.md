# Reviewing the published ISU findings

You are reviewing 116 already-published bugs. Your job is to decide which ones really depend on multiple pieces of stored state getting out of sync.

You are not checking MV-Scan. You are not re-auditing the entire project. Use only the evidence in the supplied card.

## For each row

1. Open the card in the `known_finding` column.
2. Read the root cause, consequence, and fix.
3. Ask: **Does this bug depend on two or more pieces of stored state that are supposed to agree, but become inconsistent?**
4. Enter one answer in `is_mvsi`:

   - `Y` — Yes. The relationship between multiple stored values is essential to the bug.
   - `N` — No. The bug concerns only one stored value, is not an inconsistent-state bug, or mentions other values that are not essential.
   - `U` — The card does not provide enough evidence to decide.

5. If you enter `N` or `U`, write one short reason in `correction_note`. Examples:

   - `only one stale value`
   - `other state is incidental`
   - `no inconsistent relationship shown`
   - `missing the operation that creates the inconsistency`

For `Y`, leave `correction_note` blank. There is no separate completion or final-verdict column; entering `Y`, `N`, or `U` finishes the row.

## What counts as multiple-state inconsistency?

A `Y` should have all of the following:

- At least two persistent values are involved.
- Those values have a real protocol relationship; they are not merely used near each other.
- An operation updates only part of that relationship and leaves the state inconsistent.
- The inconsistent value is later used before it is corrected.
- The bug would not exist without the relationship between those values.

You do not need to write five separate answers for these checks. Use them to make the single `Y`, `N`, or `U` decision.

## Using the cards

The top of each card reproduces the published ISU dataset's report identity, root cause, consequence, fix, and report link. Some cards also include source excerpts for a quick check. Source excerpts are supplemental and are not available for every finding.

Do not look at MV-Scan output, detector settings, another reviewer's sheet, or administrative files while doing this review.
