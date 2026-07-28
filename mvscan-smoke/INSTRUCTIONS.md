Proceed in the order below. Do not begin semantic pruning until contextual key recovery and interface dispatch both pass their Bug 112 gates.

The current checkpoint is worth preserving:

* 759 physical writer/reader block pairs.
* 361 context-qualified JSON instances.
* 271 Slither-visible results.
* 622 same-root context pairs removed.
* 77 mapping bases shadowed.
* The H‑02 relation remains present.

This is a substantial improvement over the former 1,163 block pairs, 905 relation-family instances, and 659 Slither results.  

The remaining architectural problem is specific: relation accesses are registered against physical block-level locations before execution contexts are known, relation evidence is also decided before context expansion, and an execution context currently contains only an owner and storage domain.   

The target architecture should remain incremental:

```text
existing physical ICFG
    + one unified call-target resolver
    + relation-relevant argument bindings on execution contexts
    + context-qualified relation evidence
    + owner-qualified sink evidence
    + writer-centered candidate aggregation
    + a local semantic refinement pass
```

Do not clone the CFG per root or per argument binding.

---

# Phase 2A — Introduce guarded feature switches and schema 3

Implement the following switches with defaults of `False` while each phase is being validated:

```python
MVSCAN_CONTEXTUAL_KEYS = env_bool(
    "MVSCAN_CONTEXTUAL_KEYS",
    False,
)

MVSCAN_INTERFACE_DISPATCH = env_bool(
    "MVSCAN_INTERFACE_DISPATCH",
    False,
)

MVSCAN_ROOT_CONTEXT_SINKS = env_bool(
    "MVSCAN_ROOT_CONTEXT_SINKS",
    False,
)

MVSCAN_WRITER_CENTERED = env_bool(
    "MVSCAN_WRITER_CENTERED",
    False,
)

MVSCAN_SEMANTIC_REFINEMENT = env_bool(
    "MVSCAN_SEMANTIC_REFINEMENT",
    False,
)

MVSCAN_EMIT_RECALL_STREAM = env_bool(
    "MVSCAN_EMIT_RECALL_STREAM",
    True,
)
```

Add two bounded integer settings:

```python
MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK = env_int(
    "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK",
    default=128,
    minimum=1,
)

MVSCAN_MAX_DISPATCH_TARGETS = env_int(
    "MVSCAN_MAX_DISPATCH_TARGETS",
    default=16,
    minimum=1,
)
```

## Add `env_int()` to `mvscan_env.py`

```python
def env_int(
    name: str,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name)

    if raw is None:
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            raise ValueError(
                f"{name} must be an integer, got {raw!r}"
            ) from exc

    if minimum is not None and value < minimum:
        raise ValueError(
            f"{name} must be >= {minimum}, got {value}"
        )

    if maximum is not None and value > maximum:
        raise ValueError(
            f"{name} must be <= {maximum}, got {value}"
        )

    return value
```

Add every new `MVSCAN_*` name to `_KNOWN_MVSCAN_ENV` and every effective value to `effective_config()`.

## Extend metadata

Import the configuration module itself:

```python
from .utils import mvscan_env as mvscan_env_module
```

Add its hash:

```python
"mvscan_env": _sha256_file(
    mvscan_env_module.__file__
),
```

The current metadata hashes the detector, ICFG, and alias modules but not the environment parser. 

Bump:

```python
MVSCAN_JSON_SCHEMA_VERSION = 3
```

Do not change finding semantics yet.

## Phase 2A stop gate

Run Bug 112 with every new semantic switch disabled.

Required:

```text
context-qualified JSON instances = 361
Slither-visible results          = 271
raw block pairs                  = 759
owner context pairs              = 2751
```

A schema or metadata change is allowed. Semantic counters and rendered findings must remain unchanged.

---

# Phase 2B — Create one authoritative call-target resolver

Call handling is currently divided among:

* `ICFG.add_block()`
* function influence summaries
* may/must write summaries
* branch-return inlining
* the detector’s secondary `call_edges_any`
* external-call classification

That is unsafe once interface dispatch is added. The same callsite must resolve identically in every subsystem.

The current ICFG creates a body edge only when `ir.function.entry_point` exists, while the fallback resolver is a bare-name/global-uniqueness heuristic.  

## 2B.1 Add stable callsite and target records to `icfg.py`

```python
CallSiteId = tuple[BasicBlock, int]


@dataclass(frozen=True, slots=True)
class ResolvedCallTarget:
    target_function_key: str
    resolution_kind: str
    confidence: str


@dataclass(frozen=True, slots=True)
class CallEdgeRecord:
    source_bid: BasicBlock
    target_bid: BasicBlock
    callsite_id: CallSiteId

    target_function_key: str

    storage_mode: str
    target_storage_context: str | None

    # callee placeholder -> expression in caller namespace
    substitutions: tuple[tuple[str, str], ...]

    resolution_kind: str
    confidence: str
```

Use these resolution kinds:

```text
direct_concrete
internal_unique_signature
interface_unique
interface_ambiguous
receiver_concrete
fallback_unique_signature
unresolved
```

Use these confidence values:

```text
exact
high
ambiguous
unknown
```

## 2B.2 Add ICFG fields

Inside `ICFG.__init__()`:

```python
self.call_targets_by_site: dict[
    CallSiteId,
    tuple[ResolvedCallTarget, ...],
] = {}

self.call_edges_by_source: DefaultDict[
    BasicBlock,
    set[CallEdgeRecord],
] = defaultdict(set)

self.call_resolution_stats = defaultdict(int)
```

Retain `self.call_edges` temporarily because existing reachability helpers consume it. Populate it from `CallEdgeRecord.target_bid`.

Deprecate `call_edge_context_modes`; do not remove it until the resolver-skeleton checkpoint passes.

## 2B.3 Use one callsite iterator

Use SSA IR consistently:

```python
def iter_call_sites(node):
    call_ordinal = 0

    for ir in _ssa_irs(node):
        if not isinstance(
            ir,
            (HighLevelCall, InternalCall, LibraryCall),
        ):
            continue

        callsite_id = (
            (
                function_key(node.function),
                node.node_id,
            ),
            call_ordinal,
        )

        yield callsite_id, ir
        call_ordinal += 1
```

Do not use the raw IR-array index as the callsite ordinal unless every subsystem uses the same IR representation.

## 2B.4 Build resolver indexes once

After `fn_lookup` is populated, create stable indexes:

```python
functions_by_key
functions_by_full_signature
functions_by_selector
functions_by_bare_name
functions_by_contract_and_signature
concrete_functions_by_signature
```

Use a full signature:

```python
def function_signature_key(fn) -> str:
    full_name = getattr(fn, "full_name", None)
    if full_name:
        return str(full_name)

    parameter_types = ",".join(
        str(parameter.type).replace(" ", "")
        for parameter in getattr(fn, "parameters", [])
    )

    return f"{fn.name}({parameter_types})"
```

Normalize selectors to one hex-string representation.

## 2B.5 First implement baseline-preserving resolution

Before enabling interface dispatch, the resolver should return only:

1. The direct `ir.function` when it has an entry point.
2. A same-contract unique full-signature target for unresolved internal/library calls.
3. A globally unique full-signature target only when no same-contract target exists.

Do not use a bare-name match when a parameter signature is available.

The first resolver implementation must reproduce existing results.

## 2B.6 Replace all direct callee access

Every one of these sites must use the resolver:

```text
ICFG.add_block
_analyze_function_influence
compute_function_write_summaries
branch-return summary inlining
detector call_edges_any construction
external-effect classification
path/provenance generation
```

The detector should no longer rebuild a separate call graph by reading `ir.function` directly. The current secondary call graph does exactly that. 

Instead:

```python
for edges in icfg.call_edges_by_source.values():
    for edge in edges:
        call_edges_any[
            edge.source_bid[0]
        ].add(edge.target_function_key)
```

## 2B.7 Correct may/must handling for multiple targets

When later interface dispatch produces several possible targets:

```text
may-read / may-write / sensitive effects = union
must-write effects                       = intersection
```

For write summaries:

```python
target_may_sets = []
target_must_sets = []

for target in targets:
    summary = summaries.get(
        fn_lookup[target.target_function_key]
    )

    if summary is None:
        continue

    target_may_sets.append(
        instantiate_set(summary.may_writes)
    )

    target_must_sets.append(
        instantiate_set(summary.must_writes)
    )

may_writes.update(
    set().union(*target_may_sets)
    if target_may_sets else set()
)

generated.update(
    set.intersection(*target_must_sets)
    if target_must_sets else set()
)
```

Never union ambiguous-target `must_writes`.

## Phase 2B stop gate

With:

```text
MVSCAN_INTERFACE_DISPATCH=0
MVSCAN_CONTEXTUAL_KEYS=0
```

the Bug 112 output must remain at the Phase 1 checkpoint.

Any difference means the resolver refactor changed existing call semantics and must be corrected before continuing.

---

# Phase 2C — Carry relation-relevant key bindings through execution contexts

The current execution context is:

```python
(owner, storage_context)
```

and call propagation only preserves or switches storage context. 

Extend it without cloning physical blocks.

## 2C.1 Add `ExecutionContext`

In `icfg.py`:

```python
@dataclass(frozen=True, slots=True, order=True)
class ExecutionContext:
    owner: str
    storage_context: str

    # Sorted tuple: callee formal placeholder -> canonical root expression
    bindings: tuple[tuple[str, str], ...] = ()

    @property
    def binding_map(self) -> dict[str, str]:
        return dict(self.bindings)
```

Do not include the call path in context identity. Different paths that produce the same owner, storage domain, and relevant bindings should merge.

Track path provenance separately.

## 2C.2 Represent root inputs explicitly

Seed root bindings as:

```python
def root_context_bindings(fn, owner):
    return tuple(
        (
            f"$arg{index}",
            f"@txarg::{owner}::{index}",
        )
        for index, _ in enumerate(
            getattr(fn, "parameters", []) or []
        )
    )
```

Normalize sender-sensitive terms as:

```text
@sender::<owner>
```

Do not leave every transaction’s `msg.sender` as one global literal.

## 2C.3 Canonicalize call arguments in the caller namespace

Add a helper separate from the current generic `canon_key()`:

```python
def contextual_argument_template(
    argument,
    caller_fn,
) -> str:
    parameter_index = _formal_parameter_index(
        caller_fn,
        argument,
    )

    if parameter_index is not None:
        return f"$arg{parameter_index}"

    text = norm_txt(str(argument))

    if text in {
        "msg.sender",
        "_msgsender()",
        "_msgsender",
    }:
        return "$sender"

    concrete = _non_ssa_variable(argument)

    if isinstance(concrete, StateVariable):
        return (
            "@state::"
            + source_file_key(concrete)
            + "::"
            + str(
                getattr(
                    concrete,
                    "canonical_name",
                    concrete.name,
                )
            )
        )

    if _looks_like_literal(argument):
        return f"@const::{text}"

    return (
        f"@local::{function_key(caller_fn)}::{text}"
    )
```

For the first implementation, `_looks_like_literal()` should recognize:

```text
integer literals
hex literals
true / false
address literals
bytes literals
enum literals where Slither exposes a concrete declaration
```

## 2C.4 Store call-edge substitutions

When creating each `CallEdgeRecord`:

```python
substitutions = tuple(
    sorted(
        (
            f"$arg{index}",
            contextual_argument_template(
                argument,
                caller_fn,
            ),
        )
        for index, argument in enumerate(
            getattr(ir, "arguments", []) or []
        )
    )
)
```

## 2C.5 Compose substitutions during reachability

```python
_ARG_PATTERN = re.compile(r"\$arg\d+")


def instantiate_key_template(
    template: str,
    bindings: dict[str, str],
    owner: str,
) -> str:
    current = str(template)

    if current == "$sender":
        return f"@sender::{owner}"

    for _ in range(16):
        changed = False

        def replace(match):
            nonlocal changed
            placeholder = match.group(0)

            replacement = bindings.get(
                placeholder,
                placeholder,
            )

            if replacement != placeholder:
                changed = True

            return replacement

        updated = _ARG_PATTERN.sub(
            replace,
            current,
        )

        current = updated

        if not changed:
            break
    else:
        return (
            "@unknown::recursive-substitution::"
            + current
        )

    current = current.replace(
        "$sender",
        f"@sender::{owner}",
    )

    return current
```

Do not use unrestricted substring replacement for placeholders. The current helper operates by textual replacement and is suitable only for the existing one-hop summary use. 

Compose a callee environment:

```python
def compose_callee_bindings(
    caller_context: ExecutionContext,
    edge: CallEdgeRecord,
    relevant_formals: set[str],
) -> tuple[tuple[str, str], ...]:
    caller_bindings = (
        caller_context.binding_map
    )

    composed = {}

    for placeholder, caller_template in edge.substitutions:
        if placeholder not in relevant_formals:
            continue

        composed[placeholder] = (
            instantiate_key_template(
                caller_template,
                caller_bindings,
                caller_context.owner,
            )
        )

    return tuple(sorted(composed.items()))
```

## 2C.6 Carry only relation-relevant formals

Do not carry every argument across every call.

Precompute:

```python
self.relevant_formals_by_function: dict[
    str,
    set[str],
]
```

Initial relevance comes from formal placeholders appearing in:

* Local mapping reads/writes.
* External-state argument terms.
* External-state receiver terms.
* Return-location summaries.

Then propagate relevance backward:

```text
callee $arg1 relevant
caller passes caller $arg0 into callee arg1
therefore caller $arg0 is relevant
```

Compute this to a monotone fixed point over call edges.

## 2C.7 Update `compute_entry_owners()`

The worklist becomes:

```python
deque[
    tuple[
        BasicBlock,
        ExecutionContext,
    ]
]
```

Root seed:

```python
context = ExecutionContext(
    owner=analysis_owner,
    storage_context=storage_context,
    bindings=root_context_bindings(
        root_function,
        analysis_owner,
    ),
)
```

CFG propagation preserves the context.

Call propagation:

```python
for edge in sorted(
    icfg.call_edges_by_source.get(
        block_id,
        set(),
    ),
    key=call_edge_sort_key,
):
    if edge.storage_mode == "preserve":
        next_storage_context = (
            context.storage_context
        )
    else:
        next_storage_context = (
            edge.target_storage_context
            or "<unknown-storage-context>"
        )

    target_relevant_formals = (
        icfg.relevant_formals_by_function.get(
            edge.target_function_key,
            set(),
        )
    )

    next_context = ExecutionContext(
        owner=context.owner,
        storage_context=next_storage_context,
        bindings=compose_callee_bindings(
            context,
            edge,
            target_relevant_formals,
        ),
    )

    worklist.append(
        (edge.target_bid, next_context)
    )
```

## 2C.8 Guard against context explosion

Group contexts by:

```text
block
owner
storage context
```

If more than `MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK` distinct binding environments occur, do not silently truncate.

During development:

```python
raise RuntimeError(
    "MV-Scan contextual key limit exceeded: ..."
)
```

Only introduce widening after observing a real benchmark that requires it. If widening becomes necessary, merge conflicting terms into explicit `@unknown::...` values and route resulting candidates to the recall stream.

## 2C.9 Store call-path provenance separately

Add:

```python
self.context_call_parents = defaultdict(set)
```

For each call transition:

```python
self.context_call_parents[
    (
        edge.target_bid,
        next_context,
    )
].add(
    (
        edge.source_bid,
        context,
        edge.callsite_id,
        edge.target_function_key,
        edge.resolution_kind,
        edge.confidence,
    )
)
```

Do not add these paths to `ExecutionContext.__hash__`.

A deterministic shortest call chain can later be reconstructed by walking from a function entry context to its parent callsite context.

---

# Phase 2D — Register unresolved key templates as candidates, not evidence

The new exact matching removed invalid base/slot findings, but it also lost physical helper accesses such as:

```text
currentUInts256[$arg0]
```

when the relation members are:

```text
currentUInts256[BOUND_KEY]
currentUInts256[TARGET_KEY]
```

The correct response is not to restore mapping-base wildcard matching.

## 2D.1 Add template maps to `ICFG.__init__()`

```python
self.relation_template_reads = defaultdict(
    lambda: defaultdict(set)
)

self.relation_template_writes = defaultdict(
    lambda: defaultdict(set)
)
```

Keep these distinct from:

```text
relation_reads
relation_writes
relation_unresolved_base_reads
relation_unresolved_base_writes
```

## 2D.2 Identify a potential key template

```python
def is_symbolic_key_template(key: str) -> bool:
    text = str(key)

    return (
        bool(re.search(r"\$arg\d+", text))
        or "$sender" in text
        or "msg.sender" in text
        or text.startswith("@local::")
        or text.startswith("@unknown::")
    )
```

## 2D.3 Modify `register_relation_access()`

Retain exact registration first:

```python
matched_members = matching_relation_members(
    members,
    entity,
)

if matched_members:
    ...
    return
```

Then add:

```python
if isinstance(entity, MappingSlotVar):
    same_base_members = {
        member
        for member in members
        if (
            isinstance(
                member,
                MappingSlotVar,
            )
            and member.base == entity.base
        )
    }

    if (
        same_base_members
        and is_symbolic_key_template(
            entity.key
        )
    ):
        aggregate_map[pseudo].update(
            block_ids
        )

        for block_id in block_ids:
            template_access_map[
                pseudo
            ][block_id].add(entity)

        pair_stats[
            "relation_unbound_key_templates"
        ] += len(block_ids)

        return
```

Use separate read and write template maps.

Do not register:

```text
config[FIXED_A]
```

as a candidate for:

```text
config[FIXED_B]
```

when both sides are concrete and unequal.

## 2D.4 Prune the maps

After reachability:

```python
filter_relation_access_map(
    icfg.relation_template_reads,
    keep,
)

filter_relation_access_map(
    icfg.relation_template_writes,
    keep,
)
```

## 2D.5 Add counters

```text
relation_template_read_blocks
relation_template_write_blocks
relation_template_accesses
relation_templates_contextually_resolved
relation_templates_contextually_rejected
```

Add template counts to relation metadata and the future relation catalog.

---

# Phase 2E — Move relation compatibility after context selection

This is the critical ordering correction.

Currently `_relation_access_evidence()` runs inside `stale_read_pairs()` before writer and reader contexts are enumerated.  

## 2E.1 Make `stale_read_pairs()` a physical candidate generator

For relations, remove:

```python
relation_evidence = (
    _relation_access_evidence(...)
)

if not relation_evidence:
    ...
    continue
```

`RawStateWitness` should carry only:

```python
writer_bid
reader_bid
variable
operation_pattern
writer_reaches_reader
reader_reaches_writer
```

Its relation evidence remains empty until a writer and reader execution context have been selected.

## 2E.2 Keep a broad physical prefilter

Add:

```python
def relation_block_has_candidate_access(
    icfg,
    relation,
    bid,
    kind: str,
) -> bool:
    exact_map = (
        icfg.relation_writes
        if kind == "write"
        else icfg.relation_reads
    )

    template_map = (
        icfg.relation_template_writes
        if kind == "write"
        else icfg.relation_template_reads
    )

    return bool(
        exact_map
        .get(relation, {})
        .get(bid, set())
        or template_map
        .get(relation, {})
        .get(bid, set())
    )
```

This is only a candidate prefilter. It must not create evidence.

## 2E.3 Contextualize locations lazily

In `ICFG`:

```python
self.contextual_location_cache = {}
```

```python
def contextualize_location(
    self,
    location,
    context: ExecutionContext,
):
    cache_key = (
        location,
        context.owner,
        context.bindings,
    )

    cached = (
        self.contextual_location_cache
        .get(cache_key)
    )

    if cached is not None:
        return cached

    if isinstance(location, MappingSlotVar):
        instantiated = MappingSlotVar(
            location.base,
            instantiate_key_template(
                location.key,
                context.binding_map,
                context.owner,
            ),
        )

    elif isinstance(location, ExternalStateVar):
        instantiated = ExternalStateVar(
            location.selector,
            instantiate_key_template(
                location.addr,
                context.binding_map,
                context.owner,
            ),
            tuple(
                instantiate_key_template(
                    argument,
                    context.binding_map,
                    context.owner,
                )
                for argument in location.args
            ),
        )

    else:
        instantiated = location

    self.contextual_location_cache[
        cache_key
    ] = instantiated

    return instantiated
```

## 2E.4 Add relation-key unification

An expected `$arg0` in a relation origin is a relation-local entity variable, not proof that every function’s first parameter is the same variable.

Use one shared constraint environment while matching the writer and reader members.

```python
@dataclass(frozen=True, slots=True)
class KeyEqualityConstraint:
    left: str
    right: str
    certainty: str
```

Split nested mapping keys into components:

```python
def split_key_path(key: str) -> tuple[str, ...]:
    return tuple(
        str(key).split("][")
    )
```

Implement:

```python
def concrete_key_term(term: str) -> bool:
    return (
        term.startswith("@const::")
        or term.startswith("@state::")
        or bool(re.fullmatch(r"0x[0-9a-f]+", term))
        or bool(re.fullmatch(r"\d+", term))
        or term in {"true", "false"}
    )
```

Unification rules:

1. Same strings: exact.
2. Expected relation placeholder such as `$arg0`:

   * Bind it to the observed term.
   * Repeated bindings conflict only when both observed terms are concrete and unequal.
3. Expected concrete term versus observed concrete term:

   * Must be equal.
4. Expected concrete term versus symbolic observed term:

   * Allow with an equality constraint.
5. Unknown term:

   * Allow only in the recall stream and mark `unknown`.
6. Nested key paths:

   * Path arity must match.
   * Unify component by component.

This preserves:

```text
balances[relation-user]
actionLockedBalances[relation-user]
```

even where the writer and reader expose the user through different transaction parameters, while rejecting contradictory fixed constants.

## 2E.5 Replace `_relation_access_evidence()`

New signature:

```python
def contextual_relation_access_evidence(
    icfg,
    relation,
    writer_bid,
    writer_context,
    reader_bid,
    reader_context,
):
    ...
```

Collect exact and template accesses:

```python
writer_locations = (
    set(
        icfg.relation_writes
        .get(relation, {})
        .get(writer_bid, set())
    )
    | set(
        icfg.relation_template_writes
        .get(relation, {})
        .get(writer_bid, set())
    )
)

reader_locations = (
    set(
        icfg.relation_reads
        .get(relation, {})
        .get(reader_bid, set())
    )
    | set(
        icfg.relation_template_reads
        .get(relation, {})
        .get(reader_bid, set())
    )
)
```

Contextualize every location, then match members using a shared key-constraint environment.

Extend `RelationAccessEvidence`:

```python
@dataclass(frozen=True, slots=True)
class RelationAccessEvidence:
    writer_location: Hashable
    writer_member: Hashable

    reader_location: Hashable
    reader_member: Hashable

    writer_match_kind: str
    reader_match_kind: str

    key_constraints: tuple[
        KeyEqualityConstraint,
        ...
    ] = ()

    dispatch_confidence: str = "exact"
```

Use match kinds:

```text
exact
contextual_exact
symbolic_constraint
unknown
```

Rank them in that order.

## 2E.6 Invoke evidence inside the context cross-product

After:

```text
distinct-root check
storage-context check
```

but before must-write filtering:

```python
relation_evidence = ()

if isinstance(var, MultiVarGroup):
    relation_evidence = (
        contextual_relation_access_evidence(
            icfg,
            var,
            w_bid,
            write_context,
            r_bid,
            read_context,
        )
    )

    if not relation_evidence:
        pair_stats[
            "relation_context_incompatible"
        ] += 1
        continue
```

Use this contextual evidence in `FindingWitnessRecord`.

## Phase 2E Bug 112 gate

Required:

1. No base-plus-own-slot relation returns.
2. The relation containing the two distinct exact `currentUInts256` keys reappears.
3. Its generic `_setConfig` physical access is instantiated to the correct fixed key under each caller.
4. No generic `$arg0` helper is matched against every concrete key without a proven context.
5. The H‑02 relation remains.

Do not continue to interface dispatch until this passes.

---

# Phase 2F — Add interface and abstract dispatch

Enable this only after the baseline resolver and contextual bindings are stable.

## 2F.1 Determine whether a target has a body

```python
def function_has_body(fn) -> bool:
    if fn is None:
        return False

    if getattr(fn, "entry_point", None) is None:
        return False

    contract = (
        getattr(fn, "contract_declarer", None)
        or getattr(fn, "contract", None)
    )

    if contract is None:
        return True

    return not (
        _bool_attr(contract, "is_interface")
        or _bool_attr(contract, "is_abstract")
    )
```

## 2F.2 Extract the receiver’s declared contract type

Use duck typing because Slither versions expose this differently:

```python
def receiver_contract_type(ir):
    destination = getattr(
        ir,
        "destination",
        None,
    )

    candidates = [
        destination,
        getattr(destination, "type", None),
        getattr(
            getattr(destination, "type", None),
            "type",
            None,
        ),
        getattr(
            getattr(destination, "type", None),
            "contract",
            None,
        ),
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        if (
            hasattr(candidate, "functions")
            or hasattr(candidate, "functions_declared")
        ):
            return candidate

    return None
```

Do not rely on one version-specific attribute without a fallback.

## 2F.3 Implement contract compatibility

```python
def contract_lineage(contract) -> set:
    if contract is None:
        return set()

    values = {
        contract,
    }

    for attribute in (
        "inheritance",
        "linearized_base_contracts",
        "_linearizedBaseContracts",
    ):
        values.update(
            getattr(contract, attribute, None)
            or []
        )

    return values
```

A concrete candidate is compatible when:

* Its contract is the receiver’s concrete declared contract; or
* It inherits/implements the apparent interface; or
* Its override metadata points to the apparent function; or
* The receiver type is absent, the complete signature is globally unique, and this is explicitly marked `fallback_unique_signature`.

## 2F.4 Resolution order for high-level calls

For each `HighLevelCall`:

1. Direct concrete `ir.function` with a body.
2. Concrete implementation on the receiver’s exact contract.
3. Concrete functions with the same complete signature whose contracts implement the apparent interface.
4. A globally unique complete-signature function.
5. Unresolved.

Never select by bare function name when multiple signatures or contracts exist.

## 2F.5 Multiple implementations

If one implementation remains:

```text
resolution_kind = interface_unique
confidence      = high
```

If several remain:

```text
resolution_kind = interface_ambiguous
confidence      = ambiguous
```

Create one call edge per target.

Do not merge their storage effects into one fictitious contract.

If the number exceeds `MVSCAN_MAX_DISPATCH_TARGETS`, fail loudly in strict development mode. Do not choose the first N.

## 2F.6 Update every analysis subsystem

For multiple targets:

* Influence summaries: union read/sink effects.
* Return locations: union possible return locations.
* May writes: union.
* Must writes: intersection.
* Reachability: fork target contexts.
* Path provenance: retain the exact target and resolution kind.
* Candidate confidence: ambiguous dispatch cannot be high confidence.

## 2F.7 Storage context

For a unique concrete high-level target:

```python
target_storage_context = (
    contract_storage_key(
        target_contract
    )
)
```

Internal and library calls preserve caller storage context.

High-level calls switch to the concrete target’s storage domain.

## Phase 2F Bug 112 gate

The concrete body of `StakerVault.transferFrom` must become reachable under:

```text
writer owner:
    TopUpAction.register(...)

writer storage context:
    StakerVault

call path:
    TopUpAction.register
      -> _lockFunds
      -> TopUpActionLibrary.lockFunds
      -> IStakerVault.transferFrom
      -> StakerVault.transferFrom
```

The relation must remain:

```text
balances[payer]
actionLockedBalances[payer]
```

This is the first strict H‑02 reachability gate.

Do not count direct `StakerVault.transferFrom` root findings as satisfying this gate.

---

# Phase 2G — Separate root eligibility from callee reachability

Every body should remain available as a callee. Only exposure seeding should apply the attacker model.

The current root test reduces public/external functions to “admin-like or not,” and the physical writer is also filtered before the outer root has been selected.  

## 2G.1 Add exposure classes

```python
class ExposureClass:
    ARBITRARY_USER = "arbitrary_user"
    RESOURCE_OWNER = "resource_owner"
    CONTRACT_GATED = "contract_gated"
    ROLE_GATED = "role_gated"
    PROTOCOL_ADMIN = "protocol_admin"
    VIEW_ONLY = "view_only"
```

Store:

```python
icfg.root_exposure_class_by_owner = {}
icfg.root_exposure_evidence_by_owner = {}
```

## 2G.2 Classify concrete exposures

Classification order:

1. Constructor/init: excluded.
2. View/pure: `view_only`.
3. Protocol governance/admin modifier or guard: `protocol_admin`.
4. Role membership guard: `role_gated`.
5. Guard comparing sender against a configured contract/interface address: `contract_gated`.
6. Guard proving sender owns the specific resource passed to the function: `resource_owner`.
7. Otherwise: `arbitrary_user`.

Contract-gate evidence includes patterns such as:

```text
msg.sender == action
msg.sender == controller
msg.sender == vault
authorizedActions[msg.sender]
onlyAction
onlyController
onlyStakerVault
```

Resource-owner evidence includes patterns such as:

```text
ownerOf(tokenId) == msg.sender
position.owner == msg.sender
account == msg.sender where account identifies the affected resource
```

Do not classify every sender equality as protocol administration.

## 2G.3 Canonical root policy

Canonical external-attacker roots:

```text
arbitrary_user
resource_owner
```

Optional roots under existing or new ablations:

```text
role_gated
protocol_admin
contract_gated
view_only
```

Contract-gated functions remain traversable through call edges even when not seeded.

## 2G.4 Remove the physical admin writer filter

Delete the pre-context filter:

```python
if (
    w_full in ADMIN_ONLY
    and r_full not in ADMIN_ONLY
):
    continue
```

It is based on the implementation block rather than the transaction root.

If an admin-write ablation is retained, apply it after selecting `outer_w`:

```python
writer_class = (
    icfg.root_exposure_class_by_owner[
        write_context.owner
    ]
)

if (
    ADMIN_WRITES_BENIGN
    and writer_class
        == ExposureClass.PROTOCOL_ADMIN
):
    ...
```

For the canonical run, use:

```text
ADMIN_WRITES_BENIGN=0
```

because canonical root seeding already enforces the root policy.

## Phase 2G Bug 112 gate

Expected:

* `TopUpAction.register` remains a root.
* Contract-gated `increaseActionLockedBalance` and `decreaseActionLockedBalance` are no longer arbitrary-user roots if their guards support that classification.
* Their bodies remain reachable when called through valid action flows.
* Strict H‑02 remains.

This should remove several misleading direct-root combinations without losing their effects as callees.

---

# Phase 3A — Make sensitive reads owner-qualified

The current influence pass unions `read_to_sink` from every function summary into one global sensitive-event set. 

Retain that global set for diagnostics, but stop using it as the canonical eligibility decision.

## 3A.1 Add owner-specific maps

```python
self.sensitive_read_events_by_owner = (
    defaultdict(set)
)

self.sink_sites_by_owner_and_event = (
    defaultdict(set)
)
```

After influence summaries and root owners are available:

```python
for owner, root_fn in (
    self.root_function_by_owner.items()
):
    summary = (
        self.function_influence_summaries
        .get(root_fn)
    )

    if summary is None:
        continue

    self.sensitive_read_events_by_owner[
        owner
    ].update(summary.read_to_sink)

    for sink_site, events in (
        summary.sink_reads.items()
    ):
        for event in events:
            self.sink_sites_by_owner_and_event[
                (owner, event)
            ].add(sink_site)
```

## 3A.2 Use the reader owner

Change:

```python
read_event_is_sensitive(
    bid,
    var,
)
```

to:

```python
read_event_is_sensitive(
    bid,
    var,
    context: ExecutionContext,
)
```

The canonical check uses:

```python
sensitive_read_events_by_owner[
    context.owner
]
```

Then contextualize the event location with `context.bindings`.

## 3A.3 Attach sink sites to witnesses

Add to `FindingWitnessRecord`:

```python
sink_sites: tuple = ()
```

Serialize:

```json
"sinks": [
  {
    "function_key": "...",
    "node_id": 123,
    "ir_index": 4,
    "kind": "storage_write"
  }
]
```

A reader witness without a sink site should be diagnostic only.

## 3A.4 Stop treating resolved view/pure calls as effects

The current `_is_external_effect()` returns true for essentially every remaining `Call`. 

Change high-level call handling:

```python
def callsite_is_external_effect(
    ir,
    targets,
) -> bool:
    if isinstance(
        ir,
        (InternalCall, LibraryCall, EventCall),
    ):
        return False

    if isinstance(ir, SolidityCall):
        text = str(
            getattr(ir, "function", "")
        ).lower()

        return (
            "selfdestruct" in text
            or "suicide" in text
        )

    if isinstance(ir, HighLevelCall):
        if not targets:
            # Unknown high-level call remains effectful.
            return True

        target_functions = [
            fn_lookup[
                target.target_function_key
            ]
            for target in targets
        ]

        if all(
            is_view_only(target_fn)
            for target_fn in target_functions
        ):
            return False

        return True

    return isinstance(ir, Call)
```

View/pure returns must still propagate into later real sinks.

## 3A.5 Sink-strength classification

Classify sink evidence without filtering it yet:

```text
economic_external_effect
authorization_effect
persistent_state_write
security_control
informational_control
unknown_external_effect
```

Selectors such as transfer, transferFrom, mint, burn, liquidation, reward, claim, fee, cap, and authorization updates should raise sink strength.

This is ranking metadata until the precision oracle is labeled.

## Phase 3A gate

Required:

* H‑02 reader witnesses survive under the roots that use the stale aggregate in stateful or economic behavior.
* Standalone view exposure no longer creates a primary impact witness merely because some other caller uses the same physical getter.
* The owner-specific sensitive-event digest is deterministic.

---

# Phase 3B — Preserve relation-origin semantics

The current `MultiVarGroup` identity is only its normalized member set, and `register_pseudo()` merges every origin with that same member set.  

This conflates different relational meanings.

## 3B.1 Add origin metadata

```python
@dataclass(frozen=True, slots=True)
class RelationOriginMeta:
    origin_id: str
    origin_kind: str

    function_key: str
    block_id: BasicBlock | None
    ir_index: int | None

    operator: str | None
    strength: str
```

Origin kinds:

```text
arithmetic_return
comparison_return
single_return_expression
multi_return_tuple
control_comparison
control_conjunction
control_disjunction
authorization_alternative
unknown_control
```

## 3B.2 Extend `MultiVarGroup`

```python
__slots__ = (
    "vars",
    "gid",
    "semantic_id",
    "equivalence_id",
)
```

Use:

```python
equivalence_id = tuple(
    var_key(member)
    for member in members
)

semantic_id = (
    origin_meta.origin_kind,
    origin_meta.operator,
    origin_meta.function_key,
    origin_meta.block_id,
    origin_meta.ir_index,
    equivalence_id,
)
```

Do not merge different source origins merely because their member sets are equal.

Equivalent origins can later be attached to one candidate as supporting evidence.

## 3B.3 Make returns site-sensitive

The current function-return summary retains components but ultimately flattens locations per function for relation construction. Preserve a separate map:

```python
@dataclass(frozen=True, slots=True)
class ReturnSite:
    block_id: BasicBlock
    ir_index: int
    return_index: int
```

Add:

```python
FunctionInfluenceSummary.return_locations_by_site
```

During each `Return` IR:

```python
return_site = ReturnSite(
    block_id=bid,
    ir_index=ir_index,
    return_index=return_index,
)

summary.return_locations_by_site[
    return_site
].update(logical_locations)
```

Register one relation per return site.

Required behavior:

```solidity
if (condition) return A[user];
return B[user];
```

must not produce `{A[user], B[user]}`.

This remains valid:

```solidity
return A[user] + B[user];
```

## 3B.4 Classify branch shapes

Use Slither expression classes where available. Use normalized text only as a defensive fallback.

Classify:

```text
admin || fundAdmin
```

as `authorization_alternative`, not a strong coupled-state invariant.

Classify:

```text
x + y
x - y
x == y
x <= y
x && y
```

separately.

Initial strength policy:

```text
arithmetic_return       strong
comparison_return       strong
control_comparison      supported
control_conjunction     supported
control_disjunction     weak
authorization_alternative weak
multi_return_tuple      weak unless co-consumed
unknown_control         recall
```

Do not delete weak origins. Route them to the recall stream until labeled evidence justifies stronger filtering.

## 3B.5 Emit a relation catalog

Each compilation unit should serialize every registered relation, including relations that yield no candidate:

```json
{
  "relation_id": "...",
  "equivalence_id": "...",
  "origins": [],
  "origin_kind": "arithmetic_return",
  "operator": "+",
  "strength": "strong",
  "members": [],
  "shadowed_members": [],
  "exact_read_blocks": 0,
  "template_read_blocks": 0,
  "exact_write_blocks": 0,
  "template_write_blocks": 0,
  "candidate_count": 0
}
```

This is necessary for recall diagnosis.

---

# Phase 4 — Replace transaction-pair findings with writer-centered candidates

The current primary output identity is a relation family plus an unordered transaction-context set. Storage contexts are present in JSON but omitted from the rendered Slither description, which is why 361 JSON instances collapse to 271 visible results. 

## 4.1 Add a directional candidate key

```python
@dataclass(frozen=True, slots=True)
class CandidateKey:
    mode: str

    writer_owner: str
    writer_bid: BasicBlock

    relation_id: tuple

    written_members: tuple
    potentially_stale_members: tuple
```

Modes:

```text
cross_transaction_final_state
intermediate_external_observation
same_transaction_internal
```

Do not include:

* Reader owner.
* Reader site.
* Reader storage context.
* Writer storage context.
* Current `shared_callee` flag.
* Current direct-link reentrancy heuristic.

Those belong to evidence or exposures.

## 4.2 Determine written and potentially stale members

From contextual relation evidence:

```python
written_members = frozenset(
    evidence.writer_member
    for evidence in relation_evidence
)
```

Initial conservative stale set:

```python
potentially_stale_members = (
    set(relation.vars)
    - set(written_members)
)
```

After semantic effect refinement, replace this with the members not proven repaired by successful root exit.

## 4.3 Add an accumulator

```python
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

    dispatch_kinds: set = field(
        default_factory=set
    )

    confidence_features: set = field(
        default_factory=set
    )
```

## 4.4 Aggregate after context validation

For every surviving contextual writer/reader instance:

```python
candidate = candidates.setdefault(
    candidate_key,
    CandidateAccumulator(...),
)

candidate.context_instances.add(
    context_instance_key
)

candidate.writer_exposures.add(
    (
        write_context.storage_context,
        tuple(
            sorted(
                icfg.root_exposures.get(
                    write_context.owner,
                    set(),
                )
            )
        ),
    )
)

candidate.reader_witnesses.add(
    directional_reader_witness
)
```

## 4.5 Candidate ID

Generate a stable ID:

```python
def candidate_id(key: CandidateKey) -> str:
    payload = json.dumps(
        _jsonable(key),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    return sha256(payload).hexdigest()[:20]
```

## 4.6 Stop using `frozenset` transaction identity

Writer and reader direction is essential. Do not make:

```text
writer -> reader
```

equal to:

```text
reader -> writer
```

The old transaction-set output can remain behind:

```text
MVSCAN_WRITER_CENTERED=0
```

for ablation only.

## 4.7 Stop using transitive relation-family partitioning as primary identity

`_partition_relation_families()` currently unions relations transitively when they share member pairs. 

In writer-centered mode:

* Build candidates per relation schema.
* Attach equivalent or overlapping relations as `supporting_relations`.
* Do not emit one candidate containing a transitive connected component of relation sets.

## 4.8 JSON schema 3 output

Use:

```json
{
  "schema_version": 3,
  "candidate_count": 0,
  "context_instance_count": 0,
  "reader_witness_count": 0,
  "compilation_units": [
    {
      "unit_id": "...",
      "candidate_count": 0,
      "context_instance_count": 0,
      "reader_witness_count": 0,
      "relation_catalog": [],
      "dispatch_catalog": [],
      "candidates": []
    }
  ],
  "candidates": []
}
```

Do not call all three counts “finding count.”

## 4.9 One Slither result per candidate

Render:

```text
[MV-SI candidate abc123...] {relation}
 writer root       -> TopUpAction.register(...)
 writer effect     -> StakerVault.sol:...
 written member    -> balances[payer]
 potentially stale -> actionLockedBalances[payer]
 reader witnesses  -> 12 across 5 roots
 storage exposures -> 1
 confidence        -> supported
```

Include the short candidate ID in the rendered text so Slither cannot collapse distinct candidate descriptions accidentally.

Assert:

```python
len(results) == len(candidates)
```

before returning from `_detect()`.

## Phase 4 Bug 112 gate

Required:

* JSON `candidate_count` equals detector-generated Slither result count.
* Context instances are retained under each candidate.
* The 361-versus-271 ambiguity is gone.
* H‑02 appears as one writer-centered candidate, not a separate primary candidate for every reader transaction.
* Its reader and sink evidence remains complete.

---

# Phase 5 — Add semantic effect refinement

Only begin this phase once:

1. Fixed-key contextual recovery passes.
2. Strict H‑02 has the correct outer root.
3. Writer-centered aggregation passes.

The refinement should suppress only candidates for which consistency is positively proven.

---

## 5.1 Extract storage write effects

Add:

```python
@dataclass(frozen=True, slots=True)
class WriteEffect:
    block_id: BasicBlock
    ir_index: int

    location: Hashable

    operation: str
    value_term: Hashable | None

    certainty: str
```

Operations:

```text
set
add
subtract
delete
increment
decrement
unknown
```

Use SlithIR operation classes first. Use normalized IR strings only as fallback.

`value_term` should be derived from SSA origins:

```text
formal parameter
constant
msg.sender
state read
call return
arithmetic combination
unknown
```

Do not use variable-name substrings as value equivalence.

## 5.2 Extend function summaries

```python
@dataclass(slots=True)
class FunctionEffectSummary:
    may_effects: set[WriteEffect]
    must_effects: set[WriteEffect]
```

For ambiguous dispatch:

```text
may effects  = union
must effects = intersection
```

Instantiate location and value terms through callsite bindings.

## 5.3 Prove repair after the writer

A candidate may be filtered from the final-state stream only when every potentially stale member has a compatible repair on every normal path after the writer.

For one function, use backward must-effect dataflow:

```text
OUT[block] =
    intersection(IN[successor])
    across normal successors

IN[block] =
    GEN[block] union OUT[block]
```

Exclude reverting exits from successful-state proofs.

For a writer inside a callee:

1. Compute must-effects from writer block to callee return.
2. Move to the parent callsite using stored context-call provenance.
3. Add must-effects from that callsite’s continuation.
4. Continue to the root.
5. Require the repair on every possible parent call path.

Do not filter when parent provenance or return behavior is ambiguous.

## 5.4 Require key compatibility

A companion update repairs a relation member only when:

* Its storage base matches.
* Its contextual key satisfies the relation key constraints.
* Its receiver/storage domain matches.
* Dispatch is not contradictory.

A write to `balances[userB]` does not repair stale state at `balances[userA]`.

## 5.5 Require value and sign compatibility for known relation shapes

Support a bounded set of relation templates:

### Sum invariant

```text
A + B
```

A decrement of `A` by `x` is repaired by an increment of `B` by `x`.

### Difference invariant

```text
A - B
```

Compatible signs depend on which side is changed.

### Equality

```text
A == B
```

Compatible assignments or deltas must preserve equality.

### Bound or comparison

```text
A <= B
```

Do not infer arbitrary repair algebra. Treat it as a control relation unless the effect is directly provable.

### Unknown operator

Never suppress based on guessed algebra.

H‑02’s central state movement is a sum-like transfer between:

```text
balances[payer]
actionLockedBalances[payer]
```

## 5.6 Add sibling-branch evidence

This is particularly valuable for H‑02.

For each candidate writer:

1. Find branch predicates dominating the writer callsite.
2. Compute the nearest common postdominator of the branch successors.
3. Summarize relation-relevant effects in each successor region up to that join.
4. Compare sibling regions.

High-confidence omission evidence exists when:

```text
branch A:
    performs primary value movement
    performs companion relation update

branch B:
    performs analogous primary value movement
    omits companion relation update
```

Record:

```json
"sibling_path_evidence": {
  "branch_site": "...",
  "reference_branch_effects": [],
  "candidate_branch_effects": [],
  "missing_effect": "..."
}
```

Use real dominators and postdominators. Do not approximate “dominating” by searching every node in the function.

## 5.7 Separate final-state from intermediate-state candidates

### Cross-transaction final state

Emit when the relation is not proven repaired by successful root exit.

### Intermediate external observation

Emit when:

* The relation is partial before an external effect.
* Repair occurs only afterward or is unknown.
* A callback-reachable reader may observe the partial state.

Replace the current direct-function-link reentrancy heuristic. A direct call relation between writer and reader functions is not proof of reentrancy.

## 5.8 Confidence tiers

Use deterministic rules.

### High confidence

Require all:

* Strong relation origin.
* Exact or contextually exact member matching.
* Direct or unique interface dispatch.
* Writer-centered partial effect.
* No proven final repair, or a proven externally observable prefix.
* Stateful, security, or economic sink.
* No unknown key/receiver.

### Supported

Permit one of:

* Symbolic equality constraint.
* Moderate relation origin.
* Non-economic persistent sink.
* Unique interface dispatch inferred from source compatibility.

### Recall

Any of:

* Ambiguous dispatch.
* Unknown key or receiver.
* Weak relation origin.
* View-only consequence.
* Unproven relation algebra.
* Context widening.

Do not use one opaque scalar score as the only explanation. Serialize the features producing the tier.

## 5.9 Patched-code suppression

The patched H‑02 variant must not produce a high-confidence candidate when the missing `increaseActionLockedBalance` is restored with:

* The same payer key.
* The same amount.
* The correct sign.
* Execution on the same successful path.

It may remain in a weak diagnostic stream only if some separate uncertainty is genuinely unresolved.

---

# Phase 6 — Canonicalization and soundness hardening

These items should be completed before freezing but after strict H‑02 is working.

## 6.1 External-state identity

Include external arguments in `var_key()`:

```python
if isinstance(v, ExternalStateVar):
    return (
        "EXT",
        str(v.addr),
        str(v.selector),
        tuple(v.args),
    )
```

Different accounts passed to `balanceOf` must not collapse into one external-state entity.

## 6.2 Unknown receivers

Do not intern every unresolved receiver as `"self"` or `"unknown"` globally.

Use a callsite-scoped receiver:

```text
@unknown-receiver::<function-key>::<node-id>::<call-ordinal>
```

If two receiver expressions later resolve to the same contextual term, canonicalize them then.

## 6.3 Nested mapping keys

Replace flattened strings such as:

```text
$arg0][$arg1
```

with a structured key path:

```python
@dataclass(frozen=True, slots=True)
class MappingKeyPath:
    components: tuple[str, ...]
```

Keep `.key` as a rendered compatibility property during migration.

Unify components independently.

## 6.4 Storage layout identity

Do not use the current name-only slot lookup as semantic equality.

Use:

```python
@dataclass(frozen=True, slots=True)
class StorageIdentity:
    source_file: str
    layout_contract: str

    slot: int
    byte_offset: int
    byte_width_or_type: str

    key_path: tuple
```

Parse storage layout using exact:

```text
source path
contract name
slot
offset
type
```

Do not strip leading underscores when determining equality.

The legacy slot fallback may remain diagnostic metadata but must not prove two declarations equal.

## 6.5 Storage-domain classification

Classify candidates using execution storage domains, not merely the contracts that declared the state variables.

Use:

```text
same_storage_domain
cross_storage_domain
external_state
```

Inherited base variables operating in one deployed storage domain are not cross-contract state merely because their declarations originate in different source contracts.

## 6.6 Initializer filtering

Until this is hardened, run the canonical development configuration with:

```text
INIT_ONLY_FILTER=0
```

The current implementation accepts any forward-reachable latch flip and identifies guarded entries by whether a function contains an expression mentioning the latch, rather than a true dominance/postdominance proof.

Implement:

1. Intraprocedural dominators.
2. Intraprocedural postdominators over normal exits.
3. Pre-init guard dominates the candidate write.
4. Latch transition postdominates the candidate write.
5. No user-reachable reset.
6. Every external root reaching the write satisfies the same proof.

Only then restore:

```text
INIT_ONLY_FILTER=1
```

for the canonical run.

## 6.7 Determinism

Add structural digests:

```text
call-target digest
execution-context digest
sensitive-read-event digest
relation-catalog digest
candidate digest
```

Each digest must be built from sorted structural IDs, never Python object identities.

Serialize:

* Solidity compiler version.
* Build-info digest.
* Target repository/source digest.
* `mvscan_env.py` hash.
* Candidate pipeline version.

Run with multiple `PYTHONHASHSEED` values.

The current repeated logs have stable downstream findings but differed by one sensitive event, so this must be resolved before freezing.

---

# Tests — add after the implementation phases

## 1. Resolver invariance test

With all new semantic switches disabled:

```text
Bug 112 JSON context instances = 361
Bug 112 Slither results        = 271
raw block pairs                = 759
```

This verifies the call-resolver refactor itself was neutral.

## 2. Contextual fixed-key helper

Fixture:

```solidity
mapping(bytes32 => uint256) internal config;

bytes32 constant BOUND = keccak256("BOUND");
bytes32 constant TARGET = keccak256("TARGET");

function _set(bytes32 key, uint256 value) internal {
    config[key] = value;
}

function setBound(uint256 value) external {
    _set(BOUND, value);
}

function setTarget(uint256 value) external {
    _set(TARGET, value);
}

function values()
    external
    view
    returns (uint256, uint256)
{
    return (config[BOUND], config[TARGET]);
}
```

Assert:

* Physical `_set` access is `config[$arg0]`.
* Under `setBound`, it becomes `config[BOUND]`.
* Under `setTarget`, it becomes `config[TARGET]`.
* No mapping-base wildcard evidence.
* No matching of `BOUND` to `TARGET`.

## 3. Relation-variable unification

Fixture relation:

```text
balances[$arg0]
locked[$arg0]
```

Assert:

* Writer `balances[@txarg::writer::0]`
* Reader `locked[@txarg::reader::1]`

can produce a satisfiable equality constraint.

Assert two unequal fixed constants cannot satisfy the same relation variable.

## 4. Interface unique dispatch

Fixture:

```solidity
interface IVault {
    function move(address user, uint256 amount)
        external;
}

contract Vault is IVault {
    mapping(address => uint256) balances;

    function move(address user, uint256 amount)
        external
    {
        balances[user] -= amount;
    }
}

contract Action {
    IVault vault;

    function register(uint256 amount) external {
        vault.move(msg.sender, amount);
    }
}
```

Assert:

* `Action.register` reaches `Vault.move`.
* Context owner remains `Action.register`.
* Storage domain switches to `Vault`.
* Dispatch kind is `interface_unique`.

## 5. Interface ambiguous dispatch

Add two concrete implementations.

Assert:

* Both target edges exist.
* May effects are unioned.
* Must effects are intersected.
* Candidate is not high confidence solely from dispatch.
* No first-target selection.

## 6. Contract-gated root test

Fixture:

```solidity
function update(address user, uint256 value)
    external
    onlyAction
{
    ...
}
```

Assert:

* `update` is not seeded as arbitrary-user.
* Its body remains reachable through the public action.
* Effects are attributed to the public action root.

## 7. Owner-qualified sensitivity

Use one getter called by:

* A standalone view root.
* A stateful function whose result controls a transfer or storage write.

Assert:

* The read is impact-sensitive under the stateful root.
* It is not a primary impact witness under the standalone view exposure.

## 8. Alternative return paths

```solidity
function value(address user)
    external
    view
    returns (uint256)
{
    if (flag) {
        return A[user];
    }

    return B[user];
}
```

Assert no `{A[user], B[user]}` relation.

## 9. Same-expression return

```solidity
return A[user] + B[user];
```

Assert the relation remains strong.

## 10. Authorization alternative

```solidity
require(
    msg.sender == admin
    || msg.sender == fundAdmin
);
```

Assert the relation is classified as:

```text
authorization_alternative
weak
```

and is absent from the high-confidence stream.

## 11. Writer-centered aggregation

Create one writer and several sensitive reader roots.

Assert:

```text
candidate_count = 1
context_instance_count > 1
reader_witness_count > 1
Slither outputs = 1
```

## 12. Final-state repair

Writer changes one relation member, then every successful path updates the companion member with the compatible amount and sign.

Assert no final-state candidate.

## 13. External-prefix observation

Writer temporarily changes one member, performs an external call, then repairs the companion member.

Assert:

* No final-state candidate.
* Intermediate-observation candidate remains if callback reachability exists.

## 14. Bug 112 strict positive

Require one candidate with:

```text
writer owner:
    TopUpAction.register(...)

physical effect:
    concrete StakerVault.transferFrom path

relation:
    balances[payer]
    actionLockedBalances[payer]

potentially stale:
    actionLockedBalances[payer]

dispatch:
    unique or otherwise explicitly qualified

sink:
    persistent/economic/security consequence
```

## 15. Bug 112 patched negative

Restore the missing action-locked balance increase.

Assert the strict high-confidence candidate disappears.

## 16. Multi-compilation-unit preservation

The empty second compilation unit must not erase the main unit.

## 17. Determinism

Run with:

```bash
PYTHONHASHSEED=1
PYTHONHASHSEED=2
PYTHONHASHSEED=3
```

Assert byte-identical canonical JSON and matching structural digests.

---

# Development run sequence

## Resolver-only checkpoint

```bash
env \
  PYTHONHASHSEED=1 \
  MVSCAN_STRICT_CONFIG=1 \
  MVSCAN_ABLATION=full \
  MVSCAN_INCLUDE_SCALAR_WITNESSES=0 \
  MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS=1 \
  MVSCAN_CONTEXTUAL_KEYS=0 \
  MVSCAN_INTERFACE_DISPATCH=0 \
  MVSCAN_ROOT_CONTEXT_SINKS=0 \
  MVSCAN_WRITER_CENTERED=0 \
  MVSCAN_SEMANTIC_REFINEMENT=0 \
  SINK_TEST=none \
  INIT_ONLY_FILTER=1 \
  ADMIN_WRITES_BENIGN=1 \
  USER_CALLABLE_INCLUDE_ROLE_GATED=0 \
  COARSE_DEDUP=1 \
  MERGE_OVERLOADS=0 \
  PROMOTE_MAPPING_BASE=0 \
  NOOP_WRITE_FILTER=1 \
  REQUIRE_SAME_SLOT_KEY=1 \
  ISD_JSON_OUT="$out_dir/resolver-baseline.json" \
  ../../../.venv/bin/slither . \
    --detect inconsistent_state \
    --hardhat-ignore-compile \
    --fail-none \
  >"$out_dir/resolver-baseline.log" 2>&1
```

## Contextual-key checkpoint

Change:

```text
MVSCAN_CONTEXTUAL_KEYS=1
INIT_ONLY_FILTER=0
ADMIN_WRITES_BENIGN=0
```

Required:

* Fixed-key helper relations return.
* Base-plus-own-slot relations remain absent.
* Strict H‑02 may still be absent at this point.

## Dispatch checkpoint

Change:

```text
MVSCAN_INTERFACE_DISPATCH=1
```

Required:

* `TopUpAction.register` reaches concrete `StakerVault.transferFrom`.
* Strict H‑02 relation and writer root appear.

## Owner-sensitive checkpoint

Change:

```text
MVSCAN_ROOT_CONTEXT_SINKS=1
```

Required:

* H‑02 stateful/economic readers remain.
* Standalone view-only reader multiplication falls.

## Writer-centered checkpoint

Change:

```text
MVSCAN_WRITER_CENTERED=1
```

Required:

* One detector output per candidate.
* Context and reader counts remain attached.
* No unexplained 361-versus-271 split.

## Full refinement checkpoint

Change:

```text
MVSCAN_SEMANTIC_REFINEMENT=1
MVSCAN_EMIT_RECALL_STREAM=1
```

Keep:

```text
INIT_ONLY_FILTER=0
```

until initializer proof tests pass.
