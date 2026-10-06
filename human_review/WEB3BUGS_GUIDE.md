# Reviewing MV-Scan findings from Web3Bugs

Each row points to one JSON packet. Review the packet and decide whether the reported state relationship is a real multi-variable inconsistent-state bug.

## For each row

Check the authoritative C1 through C5 definitions in order:

- **C1 — Multiple persistent entities:** `>=2` persistent-state variables participate in the defect. "Variables" may be scalar state variables, precise mapping or array locations, semantically distinct slots of one base mapping, or state-backed values obtained through external view calls when independent evidence shows that they represent persistent protocol state. Multiple names for one logical location do not satisfy C1.
- **C2 — Protocol relation:** Independent evidence must support a semantic relationship among the participating variables. Acceptable evidence includes protocol logic, documentation, tests, reports, economics, a proof of concept, a concrete trace, comments corroborated by behavior, or the documented rationale for a fix. Detector co-influence, a shared branch or return, naming similarity, and proximity are insufficient by themselves. An emitted relation may contain a semantic core of `>=2` variables; additional emitted members are recorded as over-approximation.
- **C3 — Desynchronizing partial transition:** A feasible operation changes a nonempty proper subset of the semantic relation, leaves `>=1` related entity unreconciled, and makes the relationship stale, violated, or otherwise inconsistent. It fails C3 when the omitted entity is independent, the intermediate state is permitted, reconciliation necessarily precedes relevant use, the write is a semantic no-op, or writer and reader cannot occur in one protocol execution. Feasibility requires at least one valid state, call sequence, actor set, and required external conditions, not an unprivileged attacker.
- **C4 — Omitted-member consumption before reconciliation:** `>=1` omitted relation member is read from persistent state after the desynchronizing transition and before reconciliation, and that read reaches a behaviorally relevant modeled `control`, `storage_write`, or `external_effect` sink. Record the omitted entity, exact read, consumer, sink, ordering, reconciliation point, transaction relationship, and behavioral relevance. Logging, debugging, dead computation, and outcome-insensitive uses fail C4.
- **C5 — Multi-variable essentiality:** The defect must depend essentially on the relationship between `>=2` persistent-state variables. A unary stale-variable defect fails C5 even when additional emitted entities are incidental.

Leave a C-column blank when it passes. Enter `N` only when it fails and `U` only when the supplied evidence cannot establish it. You may stop detailed review after the first clear failure.

For every candidate, set `protocol_relation_supported` to `YES`, `NO`, or `UNCERTAIN`. This records whether independent evidence supports the protocol relationship required by C2. It supports C2 and later error analysis; it is not a separate verdict.

## Choose the result

If all five checks pass, leave `label` blank. The tooling records it as `TP_MVSI`; you do not need to type another positive verdict. If any check fails, choose one label:

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
