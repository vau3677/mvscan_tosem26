# Reviewing MV-Scan findings from Web3Bugs

Each row points to one JSON packet. Review the packet and decide whether the reported state relationship is a real multi-variable inconsistent-state bug.

Do not open `ADMIN_SELECTION.json`. It reveals detector-configuration information that must stay hidden during review.

## For each row

Check C1 through C5 in order:

- **C1 — Multiple stored values:** Does the bug involve at least two persistent values?
- **C2 — Real relationship:** Is there evidence that those values are supposed to agree or move together? Being used in the same function is not enough.
- **C3 — Partial update:** Can an operation update only part of the relationship and leave it inconsistent?
- **C4 — Inconsistent value is used:** Is the stale or omitted value used before it is corrected, in a way that affects control flow, storage, or an external action?
- **C5 — Multiple values are essential:** Would the bug disappear if there were no relationship between the values? A bug involving only one stale variable fails this check.

Leave a C-column blank when it passes. Enter `N` when it fails. You may stop detailed review after the first clear failure.

## Choose the result

If all five checks pass, leave `label` blank. The tooling records it as `TP_MVSI`; you do not need to type another positive verdict.

If any check fails, choose one label:

- `VALID_OTHER_ISU` — A real inconsistent-state bug, but not a multi-variable one that passes all five checks.
- `NONBUG` — The packet does not establish a real inconsistent-state bug.
- `INSUFFICIENT_EVIDENCE` — The packet does not contain enough evidence to decide responsibly.

If you choose `NONBUG`, select the closest reason in `nonbug_primary_cause`:

- `unsupported_or_overbroad_relation` — The claimed relationship is not supported.
- `no_desynchronizing_partial_transition` — No feasible operation creates the claimed inconsistency.
- `reconciliation_precedes_consumption` — The state is corrected before the stale value matters.
- `omitted_state_not_behaviorally_consumed` — The stale value is not used in a meaningful way.
- `incompatible_context_key_or_ordering` — The reported operations cannot affect the same state in the required order.
- `analysis_abstraction_error` — The report comes from a detector-modeling mistake.

## Evidence note

Write one short sentence in `evidence_notes`. Point to a packet field or source-excerpt line. Examples:

- `Pass: balance and totalSupply diverge in the writer; the stale totalSupply reaches the withdrawal calculation.`
- `C2 fails: the two values are used together, but the packet shows no rule connecting them.`
- `C4 fails: the omitted value is refreshed before it affects an external call.`
- `Insufficient: the packet does not show which stored value is read after the update.`

Set `review_complete` to `Y` when the row is finished. This is needed because blank C-columns mean “pass,” so the tooling must be able to distinguish a completed row from an untouched row.

Work independently. Do not compare answers with another reviewer until both sheets are complete.
