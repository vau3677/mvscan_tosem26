Agreed. Those constraints materially change the freeze strategy.

The detector should be frozen as **one uniform static may-analysis**. It should not classify candidates by confidence, infer semantic bug classes, rank alarms, guess protocol intent, or suppress candidates using unproven value semantics. The current stated goal already supports this boundary: build the ICFG, restrict analysis to reachable transactions, infer multi-variable groupings, and approximate stale/destructive state interference rather than perfectly calculate all state inconsistency. 

The current build should **not** be frozen unchanged. One bounded, deletion-heavy hardening pass remains. After the changes below, freeze it and begin evaluation. Do not add another semantic phase after this.

# Canonical freeze semantics

The frozen detector should emit one candidate when all of the following hold:

1. A source expression or control sink establishes that two or more persistent locations are related by dataflow.
2. A transaction root can reach a write to at least one member.
3. A distinct transaction root can reach a sensitive read of a different member.
4. Writer and reader locations are compatible with the relation after contextual argument substitution.
5. Their storage domains are compatible.
6. The writer root is **not already proven by the ordinary must-write summary to write every member** of the relation.
7. The contextual candidate is aggregated by writer root, writer effect site, relation members, written members, and potentially stale members.

That is the entire canonical approximation.

It should not ask:

* Whether the relation is a conservation law.
* Whether the candidate is “high confidence.”
* Whether one sink is economically stronger than another.
* Whether a later write uses the correct amount or sign.
* Whether the candidate resembles a known bug.
* Whether the function, contract, or variable has a recognizable protocol-specific name.

The current strict H‑02 result must remain: `TopUpAction.register` reaches the concrete balance write and leaves `actionLockedBalances[payer]` potentially stale. 

---

# 1. Remove every ranking, stream, semantic-repair, and versioning feature

## 1.1 Delete these settings from `inconsistent_state(60).py`

Delete the declarations, `_KNOWN_MVSCAN_ENV` entries, `effective_config()` entries, and every conditional use of:

```text
USER_CALLABLE_INCLUDE_ROLE_GATED
INIT_ONLY_FILTER
ADMIN_WRITES_BENIGN
COARSE_DEDUP
MVSCAN_WRITER_CENTERED
MVSCAN_SEMANTIC_REFINEMENT
MVSCAN_EMIT_RECALL_STREAM
```

Also delete:

```python
ADMIN_ONLY
MVSCAN_JSON_SCHEMA_VERSION
```

The current configuration still exposes the ranking/stream and semantic-refinement switches, even though the canonical analysis should no longer have alternate output semantics. 

Keep these settings:

```text
MVSCAN_STRICT_CONFIG
MVSCAN_ABLATION
MVSCAN_INCLUDE_SCALAR_WITNESSES
MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS
MVSCAN_CONTEXTUAL_KEYS
MVSCAN_INTERFACE_DISPATCH
MVSCAN_ROOT_CONTEXT_SINKS
MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK
MVSCAN_MAX_DISPATCH_TARGETS

DIVERGENCE_BUDGET
USER_CALLABLE_ALWAYS
USER_CALLABLE_DENY
SINK_TEST
ATOMIC_GROUP
MERGE_OVERLOADS
PROMOTE_MAPPING_BASE
NOOP_WRITE_FILTER
REQUIRE_SAME_SLOT_KEY
ISD_JSON_OUT
```

Those retained settings are either genuine analysis ablations, explicit user overrides, or safety bounds.

## 1.2 Hardwire writer-centered output

The old transaction-pair bucket output should be deleted. Writer-centered aggregation is now the detector’s canonical output unit; it should not be an optional mode.

Delete:

* The `if MVSCAN_WRITER_CENTERED:` branch.
* Its entire legacy `else:` branch.
* `emit_var_map()`.
* `seen`.
* `COARSE_DEDUP`.
* `_partition_relation_families()`, once no other code references it.
* The legacy bucket classifications:

  * `single_var_cross_tx`
  * `multi_var_intra_contract`
  * `multi_var_cross_contract`
* The legacy aggregated shape records.

Retain one Slither `Output` per writer-centered candidate and the existing count assertion.

## 1.3 Delete confidence and stream machinery

From `CandidateAccumulator`, delete:

```python
dispatch_kinds
confidence_features
sibling_path_evidence
```

Delete from candidate JSON and CLI text:

```text
confidence
confidence_features
dispatch_kinds
sibling_path_evidence
sink strength
```

Delete the entire confidence-calculation block. It currently promotes candidates based on relation “strength,” match-kind ranking, sink presence, sibling evidence, and dispatch categories. 

Every accepted candidate should be emitted identically.

## 1.4 Delete semantic repair

Delete from `inconsistent_state(60).py`:

```python
_proven_parent_repair
_local_repair_status
_sibling_omission_evidence
_writer_dispatch_metadata
```

Delete from `icfg(48).py`:

```python
WriteEffect
FunctionEffectSummary
_effect_value_term
self.function_effect_summaries
```

Inside `compute_function_write_summaries()`, stop immediately after:

```python
self.function_write_summaries = summaries
```

Delete all code below that assignment that constructs `effect_summaries`. The current effect layer associates every block location with the first storage-writing IR in the block and then uses that approximate information to suppress candidates. 

Do not replace this with value analysis, symbolic execution, SMT, or another repair engine.

## 1.5 Retain only the existing must-write-all-members filter

Currently, `summary_covers_relation()` is bypassed when semantic refinement is enabled. Change the contextual pair loop to apply it unconditionally:

```python
if isinstance(var, MultiVarGroup):
    writer_root_fn = icfg.root_function_by_owner.get(outer_w)
    writer_summary = icfg.function_write_summaries.get(writer_root_fn)

    if (
        writer_summary is not None
        and summary_covers_relation(writer_summary, var)
    ):
        pair_stats["must_full_relation_filtered"] += 1
        continue
```

This is a suitable static approximation:

> When the writer root must write every relation member, it is not a missing-member candidate.

It does not attempt to prove value correctness, which is outside the frozen detector.

---

# 2. Remove all name-based access-control and initializer logic

The current root model still recognizes names such as `onlyAction`, `onlyController`, `onlyGovernance`, `ownerOf`, `initialize`, `setup`, and source paths containing `mock` or `test`. 

Delete all of that.

## 2.1 Delete these functions and data structures

Delete:

```python
_ROOT_TEST_PATH_MARKERS
has_inline_admin_guard
is_admin_only

ExposureClass
classify_root_exposure

latch_candidates_from_fn_guards
fn_has_post_guard_for
is_creation_phase
_intraprocedural_dominators
has_monotone_flip_write
has_reset
entry_paths_guarded
initializer_fn
passes_monotone_latch
_init_only_vars
```

Also delete:

```python
icfg.root_exposure_class_by_owner
icfg.root_exposure_evidence_by_owner
```

from `ICFG.__init__()`.

The dominator implementation itself is not objectionable, but its only current purpose is the name-driven initializer suppression. Removing the complete feature is smaller and safer than retaining dead machinery.

## 2.2 Replace `is_user_callable()` with a structural predicate

Use:

```python
def is_user_callable(fn, contextual_ids=()) -> bool:
    if fn.visibility not in {"public", "external"}:
        return False

    if getattr(fn, "is_constructor", False):
        return False

    # Standalone view roots cannot create the writer transaction.
    # Their bodies remain analyzable through stateful callers.
    if is_view_only(fn):
        return False

    candidate_ids = {
        function_key(fn),
        getattr(fn, "full_name", ""),
        *contextual_ids,
    }
    candidate_ids.discard("")

    if candidate_ids & USER_CALLABLE_DENY:
        return False

    if candidate_ids & USER_CALLABLE_ALWAYS:
        return True

    return True
```

Do not exclude:

* Initializer names.
* Role-gated functions.
* Governance functions.
* Contract-gated functions.
* Owner functions.
* Functions containing a particular modifier name.

A public or external state-changing entrypoint is a transaction root. Access restrictions affect exploitability but do not make its state transition irrelevant to MV-SI evaluation.

## 2.3 Make contract exclusion structural

Replace `_source_is_dependency()` with:

```python
def _source_is_dependency(obj) -> bool:
    source_mapping = getattr(obj, "source_mapping", None)
    return bool(getattr(source_mapping, "is_dependency", False))
```

Remove the `/node_modules/` fallback.

Replace `_root_contract_exclusion_reason()` with:

```python
def _root_contract_exclusion_reason(contract):
    if _source_is_dependency(contract):
        return "dependency"

    if _bool_attr(contract, "is_interface"):
        return "interface"

    if _bool_attr(contract, "is_library"):
        return "library"

    if _bool_attr(contract, "is_abstract"):
        return "abstract"

    return None
```

Do not detect tests, mocks, harnesses, or fixtures from filenames. Benchmark scoping belongs to the evaluation data, not to the detector’s semantics.

## 2.4 Simplify `compute_entry_owners()`

Remove:

```python
exposure_class
exposure_evidence
excluded_contract_gated
excluded_role_gated
excluded_protocol_admin
excluded_view_only
excluded_test_or_mock
```

The candidate record should contain only:

```python
candidate = {
    "entry_bid": entry_bid,
    "exposure_owner": exposure_owner,
    "implementation_owner": implementation_owner,
    "force_included": force_included,
    "implementation_is_dependency": _source_is_dependency(fn),
    "storage_context": _contract_classification_key(contract),
    "root_function": fn,
}
```

Keep inherited-exposure collapsing and multiple storage-context propagation. Those solve a genuine ICFG representation issue and do not depend on names.

## 2.5 Remove initializer-name exclusions from pair generation

In `stale_read_pairs()`, change write and read filtering from:

```python
if not (
    fn.is_constructor
    or fn.name.startswith("initialize")
)
```

to:

```python
if not fn.is_constructor
```

Also delete all initializer filtering in `_detect()` and relation normalization.

---

# 3. Remove semantic relation categories while preserving source provenance

The current relation representation assigns origin kinds and strengths such as `arithmetic_return`, `control_comparison`, `weak`, `supported`, and `strong`. 

Delete those categories, but keep the source site.

## 3.1 Replace `RelationOriginMeta`

Use:

```python
@dataclass(frozen=True, slots=True)
class RelationOrigin:
    origin_id: str
    function_key: str
    block_id: BasicBlock | None
    ir_index: int | None
    expression: str
```

Update `MultiVarGroup`:

```python
class MultiVarGroup:
    __slots__ = (
        "vars",
        "gid",
        "semantic_id",
        "equivalence_id",
        "origin",
    )

    def __init__(
        self,
        gid,
        vars_: tuple,
        semantic_id: tuple,
        equivalence_id: tuple,
        origin: RelationOrigin,
    ):
        self.gid = gid
        self.vars = vars_
        self.semantic_id = semantic_id
        self.equivalence_id = equivalence_id
        self.origin = origin
```

## 3.2 Make relation identity source-based only

Inside `register_pseudo()`:

```python
members = tuple(sorted(logical_members, key=var_key))
equivalence_id = tuple(var_key(member) for member in members)

if origin is None:
    origin = RelationOrigin(
        origin_id=str(gid),
        function_key="",
        block_id=None,
        ir_index=None,
        expression="",
    )

semantic_id = (
    origin.origin_id,
    equivalence_id,
)
```

No operator, strength, or origin-kind fields should enter relation identity.

## 3.3 Keep return-site precision without classifying expressions

For each return site:

```python
origin = RelationOrigin(
    origin_id=origin_id,
    function_key=function_key(fn),
    block_id=return_site.block_id,
    ir_index=return_site.ir_index,
    expression=return_text,
)

register_pseudo(
    origin_id,
    members,
    origin,
)
```

Delete the operator search and all return-kind assignments.

## 3.4 Keep SSA control-sink relations without parsing conditions

The current sink relation construction is useful because it uses state-read events that actually influence one control sink. Keep that dataflow.

Replace its entire `||` / `&&` / comparison classification block with:

```python
origin_id = (
    f"sink::{sink_site.block_id[0]}::"
    f"{sink_site.block_id[1]}::{sink_site.ir_index}"
)

register_pseudo(
    origin_id,
    members,
    RelationOrigin(
        origin_id=origin_id,
        function_key=sink_site.block_id[0],
        block_id=sink_site.block_id,
        ir_index=sink_site.ir_index,
        expression=expression_text,
    ),
)
```

This preserves indirect relations such as:

```solidity
x = A[user];
y = B[user];

if (x < y) {
    ...
}
```

without deciding what type of invariant the condition represents.

## 3.5 Preserve mapping-base shadowing exactly

Do not modify `normalize_relation_members()`.

It correctly removes a base mapping only when an exact slot under that base is already present, while retaining two distinct exact slots. That correction eliminated the former unary base-plus-own-slot explosion.

---

# 4. Make key identity function-qualified and case-preserving

This is the most important canonicalization correction.

The current `canon_key()` still falls back to:

```python
norm_txt(str(key))
```

which strips spaces, lowercases the expression, and loses the defining function. 

That is why unrelated locals named `key_1` can become equal.

## 4.1 Add an identity-preserving text helper

Keep `norm_txt()` for non-semantic textual diagnostics. Add:

```python
def identity_txt(value) -> str:
    text = str(value or "").replace("this.", "")
    text = re.sub(
        r"\baddress\((.+?)\)",
        r"\1",
        text,
    )
    return re.sub(r"\s+", "", text)
```

Do not lowercase canonical identifiers.

Solidity identifiers and function names are case-sensitive.

## 4.2 Replace `canon_key()`

```python
def canon_key(key, fn=None) -> str:
    parameter_index = _formal_parameter_index(
        fn,
        key,
    )

    if parameter_index is not None:
        return f"$arg{parameter_index}"

    if fn is not None:
        aliases = _function_parameter_aliases(fn)
        indexes = set(aliases.get(key, set()))
        indexes.update(
            aliases.get(
                _non_ssa_variable(key),
                set(),
            )
        )

        if len(indexes) == 1:
            return f"$arg{next(iter(indexes))}"

    text = identity_txt(key)
    lowered = text.lower()

    if lowered in {
        "msg.sender",
        "_msgsender()",
        "_msgsender",
    }:
        return "$sender"

    concrete = _non_ssa_variable(key)

    if isinstance(concrete, StateVariable):
        canonical_name = (
            getattr(concrete, "canonical_name", None)
            or getattr(concrete, "name", None)
            or str(concrete)
        )

        return (
            "@state::"
            + source_file_key(concrete)
            + "::"
            + str(canonical_name)
        )

    if _looks_like_literal(key):
        return "@const::" + text

    if fn is not None:
        return (
            "@local::"
            + function_key(fn)
            + "::"
            + type(concrete).__name__
            + "::"
            + text
        )

    return (
        "@unknown::"
        + type(concrete).__name__
        + "::"
        + text
    )
```

No bare local identifier should ever be a canonical mapping key.

## 4.3 Use one canonicalizer for call arguments

Replace `contextual_argument_template()` with:

```python
def contextual_argument_template(
    argument,
    caller_fn,
) -> str:
    return canon_key(argument, caller_fn)
```

Do not maintain separate key rules for mapping accesses and call arguments.

## 4.4 Preserve receiver and selector case

In `alias(58).py`, change:

```python
return AliasKey(
    canonical_addr.lower(),
    selector.lower(),
    tuple(str(arg) for arg in args),
)
```

to:

```python
return AliasKey(
    canonical_addr,
    str(selector),
    tuple(str(arg) for arg in args),
)
```

In `ExternalStateVar.__init__()`, replace:

```python
self.selector = selector.lower()
self.addr = (addr or "unknown").lower()
```

with:

```python
self.selector = str(selector)
self.addr = str(addr or "unknown")
```

The registry already correctly refuses an empty receiver and clears itself between compilation units. 

---

# 5. Make key unification conservative, without match rankings

The current `_unify_key()` treats two unequal non-concrete terms as symbolically equal. 

Replace that behavior.

## 5.1 Simplify the evidence records

Use:

```python
@dataclass(frozen=True, slots=True)
class KeyEqualityConstraint:
    left: str
    right: str


@dataclass(frozen=True, slots=True)
class RelationAccessEvidence:
    writer_location: Hashable
    writer_member: Hashable
    reader_location: Hashable
    reader_member: Hashable
    key_constraints: tuple[KeyEqualityConstraint, ...] = ()
```

Delete:

```text
writer_match_kind
reader_match_kind
dispatch_confidence
certainty
```

## 5.2 Add structural term predicates

```python
def _is_relation_placeholder(term: str) -> bool:
    return (
        term == "$sender"
        or bool(re.fullmatch(r"\$arg\d+", term))
    )


def _is_fixed_term(term: str) -> bool:
    return term.startswith((
        "@const::",
        "@state::",
    ))


def _is_free_runtime_term(term: str) -> bool:
    return term.startswith((
        "@txarg::",
        "@sender::",
    ))


def _is_opaque_term(term: str) -> bool:
    return term.startswith((
        "@local::",
        "@unknown::",
    ))
```

An uninstantiated `$argN` appearing on the observed side should also be treated as opaque.

## 5.3 Replace `_unify_key()`

```python
def _constraint(left: str, right: str):
    first, second = sorted((left, right))
    return KeyEqualityConstraint(first, second)


def _unify_component(
    expected: str,
    observed: str,
    bindings: dict[str, str],
    constraints: set[KeyEqualityConstraint],
) -> bool:
    if expected == observed:
        return True

    if _is_relation_placeholder(expected):
        previous = bindings.get(expected)

        if previous is None:
            bindings[expected] = observed
            return not (
                _is_opaque_term(observed)
                or _is_relation_placeholder(observed)
            )

        if previous == observed:
            return True

        if (
            _is_opaque_term(previous)
            or _is_opaque_term(observed)
            or _is_relation_placeholder(previous)
            or _is_relation_placeholder(observed)
        ):
            return False

        if (
            _is_fixed_term(previous)
            and _is_fixed_term(observed)
        ):
            return False

        constraints.add(
            _constraint(previous, observed)
        )
        return True

    if (
        _is_opaque_term(expected)
        or _is_opaque_term(observed)
        or _is_relation_placeholder(observed)
    ):
        return False

    if (
        _is_fixed_term(expected)
        and _is_fixed_term(observed)
    ):
        return False

    if (
        _is_fixed_term(expected)
        or _is_fixed_term(observed)
        or _is_free_runtime_term(expected)
        or _is_free_runtime_term(observed)
    ):
        constraints.add(
            _constraint(expected, observed)
        )
        return True

    return False


def _unify_key(
    expected: str,
    observed: str,
    bindings: dict[str, str],
    constraints: set[KeyEqualityConstraint],
) -> bool:
    expected_parts = split_key_path(expected)
    observed_parts = split_key_path(observed)

    if len(expected_parts) != len(observed_parts):
        return False

    return all(
        _unify_component(
            left,
            right,
            bindings,
            constraints,
        )
        for left, right in zip(
            expected_parts,
            observed_parts,
        )
    )
```

This permits the static existential condition:

```text
writer transaction argument == reader transaction argument
```

while rejecting:

```text
@local::<function A>::key_1
==
@local::<function B>::key_1
```

It also rejects two different fixed configuration declarations.

## 5.4 Simplify `_contextual_member_match()`

It should return only `bool`:

```python
def _contextual_member_match(
    location,
    member,
    bindings,
    constraints,
) -> bool:
    if location == member:
        return True

    if (
        isinstance(location, MappingSlotVar)
        and isinstance(member, MappingSlotVar)
    ):
        if location.base != member.base:
            return False

        return _unify_key(
            member.key,
            location.key,
            bindings,
            constraints,
        )

    if (
        isinstance(location, ExternalStateVar)
        and isinstance(member, ExternalStateVar)
    ):
        if (
            location.selector != member.selector
            or len(location.args) != len(member.args)
        ):
            return False

        pairs = [
            (member.addr, location.addr),
            *zip(member.args, location.args),
        ]

        return all(
            _unify_key(
                str(expected),
                str(observed),
                bindings,
                constraints,
            )
            for expected, observed in pairs
        )

    return False
```

## 5.5 Remove evidence ranking

In `contextual_relation_access_evidence()`, delete:

```python
rank_by_kind
best
rank
```

Collect every distinct valid member edge:

```python
evidence = set()

for writer_template in ...:
    ...
    for reader_template in ...:
        ...
        for writer_member in relation.vars:
            for reader_member in relation.vars:
                if writer_member == reader_member:
                    continue

                bindings = {}
                constraints = set()

                if not _contextual_member_match(
                    writer_location,
                    writer_member,
                    bindings,
                    constraints,
                ):
                    continue

                if not _contextual_member_match(
                    reader_location,
                    reader_member,
                    bindings,
                    constraints,
                ):
                    continue

                evidence.add(
                    RelationAccessEvidence(
                        writer_location,
                        writer_member,
                        reader_location,
                        reader_member,
                        tuple(sorted(
                            constraints,
                            key=lambda item: (
                                item.left,
                                item.right,
                            ),
                        )),
                    )
                )

return tuple(sorted(
    evidence,
    key=lambda item: (
        state_entity_sort_key(
            item.writer_location
        ),
        state_entity_sort_key(
            item.writer_member
        ),
        state_entity_sort_key(
            item.reader_location
        ),
        state_entity_sort_key(
            item.reader_member
        ),
        tuple(
            (constraint.left, constraint.right)
            for constraint
            in item.key_constraints
        ),
    ),
))
```

Update `read_event_is_sensitive()` and every other caller for the Boolean return.

---

# 6. Make high-level dispatch receiver-sensitive

The current resolver can use global signature uniqueness and can map an interface call to a repository implementation merely because it is the only implementation found. 

That caused the external CVX `totalSupply()` read to be conflated with a local OpenZeppelin `_totalSupply` body. 

## 6.1 Remove dispatch categories

Change:

```python
@dataclass(frozen=True, slots=True)
class ResolvedCallTarget:
    target_function_key: str
```

And:

```python
@dataclass(frozen=True, slots=True)
class CallEdgeRecord:
    source_bid: BasicBlock
    target_bid: BasicBlock
    callsite_id: CallSiteId
    target_function_key: str
    storage_mode: str
    target_storage_context: str | None
    substitutions: tuple[tuple[str, str], ...]
```

Delete:

```text
resolution_kind
confidence
```

from:

* Call records.
* Context parent tuples.
* Call digests.
* Dispatch JSON.
* Candidate construction.

## 6.2 Treat a function as implemented when it has an entry block

Replace `function_has_body()` with:

```python
def function_has_body(fn) -> bool:
    return (
        fn is not None
        and getattr(fn, "entry_point", None)
        is not None
    )
```

An implemented function may be declared in an abstract base contract. `entry_point` is the relevant structural fact.

## 6.3 Add a dependency predicate

```python
def declaration_is_dependency(obj) -> bool:
    source_mapping = getattr(
        obj,
        "source_mapping",
        None,
    )

    return bool(
        getattr(
            source_mapping,
            "is_dependency",
            False,
        )
    )
```

## 6.4 Replace `resolve_call_functions()`

Use this resolution order:

```python
def resolve_call_functions(
    self,
    ir,
    caller_fn,
) -> tuple:
    direct = getattr(ir, "function", None)

    if function_has_body(direct):
        return (direct,)

    signature = _call_signature_key(ir)
    caller_contract = getattr(
        caller_fn,
        "contract_declarer",
        None,
    )

    if isinstance(ir, InternalCall):
        lineage = contract_lineage(caller_contract)

        candidates = sorted({
            fn
            for fn in self.concrete_functions_by_signature.get(
                signature,
                set(),
            )
            if (
                function_has_body(fn)
                and (
                    getattr(
                        fn,
                        "contract_declarer",
                        None,
                    )
                    in lineage
                )
            )
        }, key=function_key)

        return (
            tuple(candidates)
            if len(candidates) == 1
            else ()
        )

    if isinstance(ir, LibraryCall):
        library_contract = (
            receiver_contract_type(ir)
            or getattr(
                direct,
                "contract_declarer",
                None,
            )
        )

        candidates = sorted({
            fn
            for fn in self.functions_by_contract_and_signature.get(
                (library_contract, signature),
                set(),
            )
            if function_has_body(fn)
        }, key=function_key)

        return (
            tuple(candidates)
            if len(candidates) == 1
            else ()
        )

    if not (
        self.interface_dispatch_enabled
        and isinstance(ir, HighLevelCall)
    ):
        return ()

    receiver_contract = receiver_contract_type(ir)

    if (
        receiver_contract is not None
        and not _bool_attr(
            receiver_contract,
            "is_interface",
        )
        and not _bool_attr(
            receiver_contract,
            "is_abstract",
        )
    ):
        visible_functions = sorted({
            fn
            for fn in (
                getattr(
                    receiver_contract,
                    "functions",
                    [],
                )
                or []
            )
            if (
                function_has_body(fn)
                and function_signature_key(fn)
                == signature
            )
        }, key=function_key)

        if len(visible_functions) == 1:
            return tuple(visible_functions)

        exact = sorted({
            fn
            for fn in self.concrete_functions_by_signature.get(
                signature,
                set(),
            )
            if (
                function_has_body(fn)
                and (
                    getattr(
                        fn,
                        "contract_declarer",
                        None,
                    )
                    is receiver_contract
                )
            )
        }, key=function_key)

        return tuple(exact) if len(exact) == 1 else ()

    apparent_contract = (
        getattr(direct, "contract_declarer", None)
        or getattr(direct, "contract", None)
        or receiver_contract
    )

    if apparent_contract is None:
        return ()

    # Do not infer a local implementation for an imported
    # dependency interface solely from signature uniqueness.
    if declaration_is_dependency(apparent_contract):
        return ()

    candidates = sorted({
        fn
        for fn in self.concrete_functions_by_signature.get(
            signature,
            set(),
        )
        if (
            function_has_body(fn)
            and not declaration_is_dependency(fn)
            and apparent_contract
            in contract_lineage(
                getattr(
                    fn,
                    "contract_declarer",
                    None,
                )
                or getattr(fn, "contract", None)
            )
        )
    }, key=function_key)

    if len(candidates) > self.max_dispatch_targets:
        return ()

    return tuple(candidates)
```

Critical removals:

* No global high-level `len(concrete) == 1` fallback.
* No dependency-interface-to-local-body inference.
* No bare-name matching.
* No selecting the “best” implementation.
* Multiple compatible first-party implementations are all retained as may-targets.

This remains a purely static call-graph approximation.

## 6.5 Update every caller

Change all loops from:

```python
for callee, kind, confidence in ...:
```

to:

```python
for callee in ...:
```

Change:

```python
ResolvedCallTarget(
    function_key(callee),
    kind,
    confidence,
)
```

to:

```python
ResolvedCallTarget(
    function_key(callee),
)
```

Change context parent records to:

```python
(
    edge.source_bid,
    execution_context,
    edge.callsite_id,
    edge.target_function_key,
)
```

Update `_shortest_call_chain()` for the four-element tuple.

The dispatch catalog should contain only:

```json
{
  "callsite": ...,
  "targets": [
    "contracts/...::Contract.function(...)"
  ]
}
```

---

# 7. Replace selector/name-based external state with a generic view-return abstraction

Current external-state handling hardcodes getter and mutator names and maps storage variables with names such as `_balances` and `_lastBalance` into external wrappers.  

Remove all of that.

## 7.1 Delete these constants

From `icfg(48).py`, delete:

```python
EXT_READS
EXT_WRITES
STORAGE_TO_SELECTOR
```

## 7.2 Delete name-based local-storage aliases

Inside `ICFG.add_block()`, delete:

* `Map local storage writes to external-state abstractions`.
* The `ERC-20 balance mapping writes should alias EXT::balanceof` block.
* The `_lastBalance` public-getter block.

These blocks rely on source-level names and are not universal storage semantics. 

## 7.3 Retain return summaries for one-location getters

Current `precompute_return_summaries()` discards functions unless their aggregate return contains at least two locations. 

Change:

```python
if len(all_locations) < 2:
    continue
```

to:

```python
if not all_locations:
    continue
```

Continue registering an MV relation only when `register_pseudo()` sees at least two members.

This allows concrete getters returning one storage location to be inlined at callsites without turning those unary getters into relations.

## 7.4 Add one generic external receiver helper

```python
def external_receiver_term(
    ir,
    caller_fn,
    callsite_id,
) -> str:
    destination = getattr(
        ir,
        "destination",
        None,
    )

    if destination is None:
        return (
            "@unknown-receiver::"
            + callsite_id[0][0]
            + "::"
            + str(callsite_id[0][1])
            + "::"
            + str(callsite_id[1])
        )

    term = canon_key(
        destination,
        caller_fn,
    )

    if term:
        return term

    return (
        "@unknown-receiver::"
        + callsite_id[0][0]
        + "::"
        + str(callsite_id[0][1])
        + "::"
        + str(callsite_id[1])
    )
```

## 7.5 Add one generic external read abstraction

```python
def external_view_location(
    ir,
    caller_fn,
    callsite_id,
):
    if not ENABLE_EXTERNAL_STATE:
        return None

    if not isinstance(ir, HighLevelCall):
        return None

    apparent = getattr(ir, "function", None)

    if apparent is None or not is_view_only(apparent):
        return None

    if getattr(ir, "lvalue", None) is None:
        return None

    return ExternalStateVar(
        _call_signature_key(ir),
        external_receiver_term(
            ir,
            caller_fn,
            callsite_id,
        ),
        tuple(
            canon_key(argument, caller_fn)
            for argument in (
                getattr(ir, "arguments", [])
                or []
            )
        ),
    )
```

This is API-independent:

```text
receiver
full call signature
canonical arguments
```

No `balanceOf`, `totalSupply`, `transfer`, `mint`, `burn`, or `sync` names are required.

## 7.6 Use the same helper in both analysis paths

### In `ICFG.add_block()`

After resolving and inlining concrete return summaries:

```python
instantiated_returns = set()

for callee in resolved_functions:
    if callee not in self.fn_returns:
        continue

    instantiated_returns.update(
        _subst_returns_with_args(
            callee,
            ir,
            self.fn_returns[callee],
            fn,
        )
    )

reads.update(instantiated_returns)

if not instantiated_returns:
    external_location = external_view_location(
        ir,
        fn,
        callsite_id,
    )

    if external_location is not None:
        reads.add(external_location)
```

Delete the current selector-table external abstraction. 

### In `_analyze_function_influence()`

Track whether the resolved call summary produced any returned state locations.

Only when it did not, call the same `external_view_location()` helper and originate the call’s lvalue from that location.

The call ordinal used there must be calculated by the same rule as `iter_call_sites()`.

## 7.7 Do not synthesize external writes

An unresolved non-view external call should remain:

```text
external-effect sink
```

It should not be converted into a speculative storage location.

Without an interface specification, the detector cannot generally infer which getter-visible external state an arbitrary mutating function changes. Inventing that mapping is precisely the kind of hardcoded semantic behavior being removed.

## 7.8 Correct view-call sink handling

In `_sensitive_operation_kind()`, exclude an apparent view/pure call even when no concrete target was resolved:

```python
if isinstance(ir, HighLevelCall):
    apparent = getattr(ir, "function", None)

    if (
        apparent is not None
        and is_view_only(apparent)
    ):
        return None
```

Its returned value can still flow into a later control, storage-write, or external-effect sink.

---

# 8. Simplify witness and candidate construction

## 8.1 Remove operation-pattern categories

Delete `classify_witness_operation()` and the strings:

```text
cross_tx_stale_read
stale_read
destructive_write
cyclic_state_inconsistency
unordered_state_inconsistency
reentrant_stale_read
reentrant_destructive_write
```

Change `RawStateWitness` to:

```python
@dataclass(frozen=True, slots=True)
class RawStateWitness:
    writer_bid: BasicBlock
    reader_bid: BasicBlock
    variable: object
    writer_reaches_reader: bool
    reader_reaches_writer: bool
    relation_evidence: tuple[
        RelationAccessEvidence,
        ...
    ] = ()
```

For different physical functions:

```python
writer_reaches_reader = False
reader_reaches_writer = False
```

For the same physical function, retain the existing two CFG-reachability calculations.

These are raw facts rather than a named finding category.

## 8.2 Update `FindingWitnessRecord`

Remove:

```python
operation_pattern
```

Add:

```python
writer_reaches_reader: bool = False
reader_reaches_writer: bool = False
```

Serialize the two Booleans directly.

## 8.3 Remove shape heuristics

Delete:

```python
shapes_by_key
shared_callee
reentrant
call_edges_intra
call_edges_any
```

The call path remains available as evidence. No speculative reentrancy label is needed.

## 8.4 Collect records directly

Replace transaction-set buckets with:

```python
all_records: set[FindingWitnessRecord] = set()
```

After a contextual pair passes all filters:

```python
all_records.add(pair_record)
```

No `tx_id` or legacy bucket is required for canonical writer-centered output.

## 8.5 Simplify candidate records

Use:

```python
@dataclass(frozen=True, slots=True)
class CandidateKey:
    writer_owner: str
    writer_bid: BasicBlock
    relation_id: tuple
    written_members: tuple
    potentially_stale_members: tuple


@dataclass
class CandidateAccumulator:
    key: CandidateKey
    relation: object

    context_instances: set = field(
        default_factory=set
    )
    writer_exposures: set = field(
        default_factory=set
    )
    reader_witnesses: set = field(
        default_factory=set
    )
    sink_sites: set = field(
        default_factory=set
    )
    call_paths: set = field(
        default_factory=set
    )
    key_constraints: set = field(
        default_factory=set
    )
    supporting_origins: set = field(
        default_factory=set
    )
```

Update `candidate_id()` to omit `mode`.

## 8.6 Replace candidate assembly

The assembly loop becomes:

```python
candidates = {}

for record in sorted(
    all_records,
    key=witness_sort_key,
):
    relation = record.subject

    if not isinstance(
        relation,
        MultiVarGroup,
    ):
        continue

    written_members = frozenset(
        evidence.writer_member
        for evidence
        in record.relation_evidence
    )

    potentially_stale = (
        set(relation.vars)
        - set(written_members)
    )

    if not potentially_stale:
        continue

    key = CandidateKey(
        writer_owner=record.writer_owner,
        writer_bid=record.writer_bid,
        relation_id=relation.equivalence_id,
        written_members=tuple(sorted(
            (
                var_key(member)
                for member in written_members
            ),
            key=repr,
        )),
        potentially_stale_members=tuple(
            sorted(
                (
                    var_key(member)
                    for member
                    in potentially_stale
                ),
                key=repr,
            )
        ),
    )

    candidate = candidates.setdefault(
        key,
        CandidateAccumulator(
            key=key,
            relation=relation,
        ),
    )

    candidate.context_instances.add((
        record.writer_owner,
        record.writer_storage_context,
        record.reader_owner,
        record.reader_storage_context,
        record.writer_bid,
        record.reader_bid,
    ))

    candidate.writer_exposures.add((
        record.writer_storage_context,
        tuple(sorted(
            icfg.root_exposures.get(
                record.writer_owner,
                set(),
            )
        )),
    ))

    candidate.reader_witnesses.add(
        record
    )
    candidate.sink_sites.update(
        record.sink_sites
    )
    candidate.call_paths.add(
        _shortest_call_chain(
            icfg,
            record,
        )
    )
    candidate.supporting_origins.update(
        icfg.relation_origins.get(
            relation,
            set(),
        )
    )

    for evidence in record.relation_evidence:
        candidate.key_constraints.update(
            evidence.key_constraints
        )
```

Do not select a “stronger” relation origin. Relations with the same equivalence ID have the same logical members; attach all source origins.

## 8.7 Emit one neutral candidate

Each candidate JSON object should contain only:

```text
candidate_id
writer_owner
writer_block
relation members
supporting origin sites
written members
potentially stale members
context instances
reader witnesses
sink sites with raw IR kind
call paths
key equality constraints
```

Do not include:

```text
mode
confidence
strength
origin_kind
operator
sink strength
dispatch kind
storage-domain classification
sibling evidence
```

The writer and reader contexts already expose the actual storage domains.

## 8.8 Make Slither’s required classification neutral

Slither requires detector-level classifications. Use:

```python
IMPACT = DetectorClassification.INFORMATIONAL
CONFIDENCE = DetectorClassification.INFORMATIONAL
```

These are framework boilerplate and apply uniformly to every result.

CLI output:

```python
lines = [
    f"\n[MV-SI candidate {cid}] "
    f"{relation.name}",

    f"\n writer root       -> "
    f"{key.writer_owner}",

    f"\n writer effect     -> "
    f"{writer_file}:{writer_line}",

    "\n written member    -> "
    + ", ".join(
        map(str, key.written_members)
    ),

    "\n potentially stale -> "
    + ", ".join(
        map(
            str,
            key.potentially_stale_members,
        )
    ),

    f"\n reader witnesses  -> "
    f"{len(witnesses)}",

    f"\n storage exposures -> "
    f"{len(candidate.writer_exposures)}",
]
```

---

# 9. Simplify the JSON artifact without version numbering

The current artifact includes both schema and pipeline version fields and computes top-level compilation metadata from whichever compilation unit invoked `_record_json_unit()` last.  

## 9.1 Remove version fields

Delete:

```text
schema_version
candidate_pipeline_version
```

from:

* `detector_metadata()`
* The top-level document.
* Every unit.

Keep:

```text
detector name
Python version
Slither version
source hashes
compiler version
target source digest
build-info digest
effective configuration
structural digests
```

Those support research reproducibility.

## 9.2 Store compilation metadata per unit

When recording a unit:

```python
state.units[unit_id] = {
    "unit_id": unit_id,
    "compilation_metadata":
        compilation_metadata(detector),
    "stats": dict(
        sorted(unit_stats.items())
    ),
    "relations": list(
        relation_catalog
    ),
    "calls": list(
        dispatch_catalog
    ),
    "candidates": findings,
    "candidate_count": len(findings),
    "context_instance_count": sum(
        finding.get(
            "context_instance_count",
            0,
        )
        for finding in findings
    ),
    "reader_witness_count": sum(
        finding.get(
            "reader_witness_count",
            0,
        )
        for finding in findings
    ),
}
```

Remove top-level:

```python
"compilation_metadata":
    compilation_metadata(detector)
```

That prevents the empty secondary unit from supplying metadata for the main unit.

## 9.3 Use one candidate collection

The final document can remain simple:

```python
document = {
    "detector": detector_metadata(),
    "effective_config": effective_config(),
    "candidate_count": sum(
        unit["candidate_count"]
        for unit in ordered_units
    ),
    "context_instance_count": sum(
        unit["context_instance_count"]
        for unit in ordered_units
    ),
    "reader_witness_count": sum(
        unit["reader_witness_count"]
        for unit in ordered_units
    ),
    "compilation_units": ordered_units,
}
```

Do not duplicate candidates under both `findings` and `candidates`.

## 9.4 Simplify relation catalog entries

Use:

```python
{
    "relation_id":
        repr(relation.equivalence_id),

    "source_origins":
        sorted(
            icfg.relation_origins[
                relation
            ]
        ),

    "members": [
        var_meta(member, icfg)
        for member in relation.vars
    ],

    "shadowed_members": [...],

    "exact_read_blocks": ...,
    "template_read_blocks": ...,
    "exact_write_blocks": ...,
    "template_write_blocks": ...,
}
```

No relation category or strength.

## 9.5 Update comments

Replace:

```text
future dynamic exploit generator
```

with:

```text
static evaluation and reproducibility
```

The current header and pipeline comments still describe future dynamic generation.  

---

# 10. `mvscan_env(3).py` and `alias(58).py`

## `mvscan_env(3).py`

The parsing helpers are appropriate and require no redesign. 

Only remove the deleted option names from the detector’s known-option set. No new configuration is required.

## `alias(58).py`

Make only the case-preservation change described above. The nonempty receiver requirement and cache-reset method should remain.

---

# 11. Tests required before freezing

Leave tests until all code changes are complete, as requested.

## 11.1 Mapping relation tests

### Base plus own slot

Input:

```text
balances
balances[user]
```

Expected:

```text
logical members:
    balances[user]

relation rejected as unary
```

### Distinct same-base slots

Input:

```text
config[KEY_A]
config[KEY_B]
```

Expected:

```text
both members retained
```

## 11.2 Key canonicalization tests

### Function-local collision

```solidity
function a() {
    bytes32 key = ...;
    config[key] = 1;
}

function b() {
    bytes32 key = ...;
    config[key] = 2;
}
```

Expected canonical terms:

```text
@local::<a function key>::...::key
@local::<b function key>::...::key
```

They must not unify.

### Fixed-key propagation

```solidity
function _set(bytes32 key, uint256 value) internal {
    config[key] = value;
}

function setA(uint256 value) external {
    _set(KEY_A, value);
}

function setB(uint256 value) external {
    _set(KEY_B, value);
}
```

Expected:

```text
setA writes config[@state::...::KEY_A]
setB writes config[@state::...::KEY_B]
```

Neither may be attributed to the other key.

### Cross-transaction entity equality

For a relation:

```text
A[$arg0]
B[$arg0]
```

a writer using one root argument and a reader using another root argument must be retained with an explicit equality constraint between the two transaction arguments.

### Unbound helper argument

A helper access still containing an observed `$arg0` after context propagation must not match a fixed key or a different runtime term.

## 11.3 Dispatch tests

### First-party interface

A project-defined interface with one compatible first-party implementation should reach the concrete body.

### Imported interface

An imported interface call through an interface-typed external receiver must not resolve to a repository implementation merely because one matching implementation exists.

This test should cover the structural form that caused:

```text
local _totalSupply
external CVX totalSupply()
```

The family visible in the current run must disappear. 

### Multiple first-party implementations

All compatible implementations should be returned when the count is under the configured cap. No target should be preferred.

## 11.4 External-state tests

### Concrete unary getter

A concrete getter returning one state location should inline that location.

It should not simultaneously produce a generic external wrapper.

### Unresolved view getter

Two calls with:

* The same receiver term.
* The same signature.
* The same canonical arguments.

should produce the same `ExternalStateVar`.

Different callsite-scoped unknown receivers should remain different.

### No bare temporaries

No external receiver or argument entity key may be simply:

```text
tmp_1234
key_1
ref_1234
```

A local term may contain that source name only under its complete function-qualified identity.

## 11.5 Relation-source tests

### Alternative returns

```solidity
if (condition) {
    return A[user];
}

return B[user];
```

Expected:

```text
no A/B relation
```

### Same-expression return

```solidity
return A[user] + B[user];
```

Expected:

```text
A/B relation retained
```

### Indirect control influence

```solidity
uint256 x = A[user];
uint256 y = B[user];

if (x < y) {
    ...
}
```

Expected:

```text
A/B relation retained
```

No relation category should be assigned.

## 11.6 Candidate-output tests

Assert:

```text
one Slither result per candidate
```

Assert that neither CLI nor JSON contains:

```text
confidence
supported
recall
high
strength
origin_kind
schema_version
pipeline_version
sibling_path_evidence
```

Assert that each candidate contains:

```text
writer root
writer effect
relation
written members
potentially stale members
reader witnesses
source origins
```

## 11.7 Bug 112 integration assertions

The canonical H‑02 candidate must remain:

```text
writer root:
    TopUpAction.register

writer effect:
    concrete StakerVault balance write

relation:
    balances[payer]
    actionLockedBalances[payer]

written:
    balances[payer]

potentially stale:
    actionLockedBalances[payer]
```

Do **not** require every other candidate involving those two members to disappear. Eliminating every such false positive would require interpreting the aggregate as a conservation or transfer invariant, which is outside the selected approximation.

The unrelated configuration-key family must disappear. In the current run, functions such as `executePerformanceFee()` are incorrectly shown as writing the keeper-required-stake key. 

No base-plus-own-slot relation may return.

## 11.8 Determinism tests

Run with:

```text
PYTHONHASHSEED=1
PYTHONHASHSEED=2
PYTHONHASHSEED=3
```

Require:

* Identical candidate count.
* Identical candidate IDs.
* Identical call-target digest.
* Identical execution-context digest.
* Identical relation digest.
* Identical candidate digest.
* Byte-identical JSON after excluding no fields—there should be no timestamps or process IDs.

## 11.9 Cross-repository smoke tests

Before freezing, run the exact same detector configuration on at least two other Web3Bugs repositories.

Do not:

* Tune names.
* Add selectors.
* Add contract-specific exclusions.
* Change context caps unless the run fails and the same new bound is then used globally.

Required smoke result:

```text
analysis completes
JSON is valid
result/candidate counts agree
no canonicalization invariant fails
no context-accounting assertion fails
```

The findings need not be labeled before the freeze. Their evaluation occurs after the detector is frozen.

---

# 12. Final canonical run command

After deleting the removed options, use:

```bash
env \
  PYTHONHASHSEED=1 \
  MVSCAN_STRICT_CONFIG=1 \
  MVSCAN_ABLATION=full \
  MVSCAN_INCLUDE_SCALAR_WITNESSES=0 \
  MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS=1 \
  MVSCAN_CONTEXTUAL_KEYS=1 \
  MVSCAN_INTERFACE_DISPATCH=1 \
  MVSCAN_ROOT_CONTEXT_SINKS=1 \
  MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK=128 \
  MVSCAN_MAX_DISPATCH_TARGETS=16 \
  SINK_TEST=none \
  MERGE_OVERLOADS=0 \
  PROMOTE_MAPPING_BASE=0 \
  NOOP_WRITE_FILTER=1 \
  REQUIRE_SAME_SLOT_KEY=1 \
  ISD_JSON_OUT=/tmp/mvscan-runs/frozen.json \
  ../../../.venv/bin/slither . \
    --detect inconsistent_state \
    --hardhat-ignore-compile \
    --fail-none \
  > /tmp/mvscan-runs/frozen.log 2>&1
```

These options should no longer exist and therefore must not appear:

```text
MVSCAN_WRITER_CENTERED
MVSCAN_SEMANTIC_REFINEMENT
MVSCAN_EMIT_RECALL_STREAM
INIT_ONLY_FILTER
ADMIN_WRITES_BENIGN
USER_CALLABLE_INCLUDE_ROLE_GATED
COARSE_DEDUP
```

---

# Freeze gate

Freeze immediately after all of the following hold:

1. Strict H‑02 remains visible under `TopUpAction.register`.
2. Mapping bases are not treated as separate variables from their own exact slots.
3. Fixed configuration keys remain distinct through helper calls.
4. Function-local unresolved terms cannot collide across functions.
5. Imported interface calls do not enter unrelated local implementation bodies.
6. First-party interface dispatch still reaches compatible first-party bodies.
7. Concrete unary getters inline their actual state location.
8. Unresolved view calls use receiver-, signature-, and argument-qualified external identities.
9. No name-based admin, role, initializer, test, mock, token, getter, or storage-variable rule remains.
10. No candidate ranking, confidence stream, semantic relation category, or repair inference remains.
11. No schema or pipeline version appears in the artifact.
12. One Slither output corresponds to one writer-centered candidate.
13. The three hash-seed runs are identical.
14. Two additional Web3Bugs repositories complete without detector-specific changes.

There should be **no target candidate count**. The final number is whatever remains after mechanically invalid identities and unsound dispatch edges are removed.

At that point, further precision work would require choosing stronger semantic assumptions about what relations mean. Under the constraints you set, that work belongs after evaluation as a documented future extension—not before the detector freeze.

