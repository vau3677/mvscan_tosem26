# Web3Bugs Bucket Review Guide

Review one packet and fill one row at a time. Do not open `ADMIN_SELECTION.json`;
it contains configuration membership used later by the analysis team. Packets
are intentionally configuration-blind and already deduplicated.

Leave passing C1--C5 fields blank and enter `N` only for failed criteria. Set `review_complete=Y` after reviewing the row. Blank criteria on a completed row normalize to `Y`.

When all five criteria pass, leave `label` blank and derive `TP_MVSI`. Otherwise assign exactly one label:

- `VALID_OTHER_ISU`: a real inconsistent-state issue, but not MV-SI.
- `NONBUG`: the evidence does not establish a real inconsistent-state issue.
- `INSUFFICIENT_EVIDENCE`: the bounded packet cannot support a responsible decision.

For `NONBUG`, select exactly one primary cause:

- `unsupported_or_overbroad_relation`
- `no_desynchronizing_partial_transition`
- `reconciliation_precedes_consumption`
- `omitted_state_not_behaviorally_consumed`
- `incompatible_context_key_or_ordering`
- `analysis_abstraction_error`

Evidence notes must cite packet fields or excerpt line numbers; a short sentence is sufficient. Save progress
after every row. Reviewers must not compare their sheets before adjudication.

The packet is a lead, not proof: detector co-use alone does not establish C2;
the reviewer must confirm feasible ordering, behavioral consumption, and the
essential multi-variable relationship. Use `INSUFFICIENT_EVIDENCE` when the
packet truly cannot decide the question; the research team can perform a
targeted escalation rather than making every reviewer browse a repository.
