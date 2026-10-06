# Cross-Ablation Structural-Union Amendment

Date: 2026-08-19

## Reason

The original evaluation design made a cross-configuration structural-signature
bucket the manual-review and ablation unit. During protocol simplification, the
sampling frame was inadvertently narrowed to B0 native candidates and the
construction of `global_candidate_id` was no longer defined. The discrepancy
was discovered after detector execution but before F2 selection, candidate
annotation, adjudication, or precision estimation. No labels or selection are
being discarded.

This amendment restores the original cross-ablation intent using fields that
are present in the frozen detector JSON. It does not change detector output,
configuration, subject, seed, or run status.

## Structural unit

For each successful Web3Bugs seed-0 run, each native detector candidate that
passes the already frozen source-scope frame is converted to
a variant-independent structural payload containing:

- dataset, subject, and revision role;
- normalized writer owner and writer block function/node;
- sorted canonical relation-member entity keys;
- sorted written-member and potentially-stale-member entity keys;
- sorted writer/reader transaction-context owners;
- sorted modeled sink kinds; and
- derived shape tags: relation arity and sorted entity kinds.

JSON values are encoded canonically. Missing required values fail population
construction; they are never represented by a shared null token. The full
SHA-256 of the canonical payload is `global_candidate_id`. Configuration,
seed, candidate-local short ID, witness count, individual witness paths, and
source line numbers are not part of this identity. The latter fields remain
provenance/evidence.

This rule merges the same structural candidate across configurations while
preventing candidates from different subjects or revisions from merging.
Configuration-induced changes to state identity, written/omitted roles,
transaction contexts, or sink shape remain distinct buckets and are therefore
eligible for review.

## Population and sampling

Construct the complete union of structural buckets across B0, A1, A2, A4, and
A5 from successful Web3Bugs seed-0 runs. Candidate entry requires an in-scope
writer, at least one in-scope relation origin, and at least one witness with an
in-scope reader and modeled sink, exactly as frozen before execution. Frame
exclusions are counted but not labeled. Each bucket records its configuration-membership
vector and all source candidate references.

Compiler paths are resolved against the frozen checkout-relative source table
by exact match and then by unique path-suffix match. This accounts for native
projects whose compilation root is below the checkout root. An unmatched path
beginning with `node_modules/` or a package alias beginning with `@` is a
separately versioned dependency and is out of scope. As required by the frozen
binary rule, any other unmatched first-party-looking source remains in scope;
a missing path fails population construction.

ISU outputs remain outside the candidate-precision union. Each configuration is
evaluated on ISU through the complete historical semantic-match census.

For each configuration independently:

```text
if N_config <= 400: select every bucket
else: select the 400 buckets with the lowest
      SHA-256("20260811" || global_candidate_id)
```

Using the same hash domain coordinates selection and maximizes overlap without
changing the equal inclusion probability within any configuration. Merge the
five selected sets by `global_candidate_id`; reviewers label each unique bucket
once, and that label is projected to every selected configuration membership.

Select up to 200 unique reviewed buckets for independent agreement review using
the lowest `SHA-256("20260811:agreement" || global_candidate_id)` values.

Report Wilson 95% intervals separately for each configuration. B0 remains the
primary precision result; ablation precision estimates are secondary. Report
population and sample overlap, configuration-only buckets, membership patterns,
historical recovery, runtime, memory, failures, and candidate-count changes.

## Audit timing

The completed raw runs remain immutable. This amendment and its implementation
must be hashed into a superseding technical seal before F2 population or sample
artifacts are frozen.
