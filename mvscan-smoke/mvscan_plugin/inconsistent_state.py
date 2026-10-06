"""
MV-Scan is a static may-analysis for candidate multi-variable state inconsistency (MV-SI).
We do not verify invariants, path feasibility, or exploitability via symbolic execution.

For each inferred relation R, the writer must update one or more members of R, but not all.
The reader must read at least one member that the writer did not update.
This read must come from persistent state and reach a sensitive operation.

Each relation is treated as a hypothesis for manual validation.
Each candidate records the relation, writer, reader, execution context, constraint, and provenance.

This file controls the analysis workflow. It defines the configuration, orchestrates the ICFG,
determines reachability from external roots, registers inferred relations, expands execution contexts,
checks candidate conditions, aggregates results, and produces JSON.
"""
import importlib.metadata
import json, os, platform, sys
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import List, Set
from collections import defaultdict, deque
from eth_utils import keccak
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output
from slither.core.variables import StateVariable
from slither.slithir.operations import HighLevelCall, InternalCall
from .utils import icfg as icfg_module
from .utils import mvscan_env as mvscan_env_module
from .utils.icfg import (
    ICFG, stale_read_pairs, BasicBlock, ExternalStateVar, MappingSlotVar,
    ExecutionContext, compose_callee_bindings, root_context_bindings,
    branch_types, reachable_without_overwrite, function_key, source_file_key,
    ENABLE_BRANCH_GROUPS, ENABLE_MULTI_RETURN_GROUPS, relation_member_is_eligible,
    location_matches_member, matching_relation_members,
    is_symbolic_key_template,
    contextual_relation_access_evidence,
    effective_relation_write_members,
    sensitive_relation_member_events,
    state_entity_sort_key,
    attr, bool_attr, declaration_is_dependency,
    reset_icfg_analysis_caches
)
from .utils.mvscan_env import env_bool, env_csv, env_enum, env_int, reject_unknown_prefixed_environment

# Parses DIVERGENCE_BUDGET (0: no traversal | 0<n<inf bounds to n | None: unbounded)
def _parse_divergence_budget():
    raw = os.getenv("DIVERGENCE_BUDGET", "1000").strip().lower()
    if raw in {"inf", "infinite", "unlimited", "unbounded"}: return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"Expected int or 'unbounded' for DIVERGENCE_BUDGET, got {raw!r}") from exc
    return None if value < 0 else value

### Global caches and configuration options

# Helpful ablation flags
DIVERGENCE_BUDGET = _parse_divergence_budget() # Cap forward-slice by CFG nodes (DivertScan §4.2.3 extension)
USER_CALLABLE_ALWAYS: Set[str] = set(env_csv("USER_CALLABLE_ALWAYS"))
USER_CALLABLE_DENY: Set[str] = set(env_csv("USER_CALLABLE_DENY"))
ATOMIC_GROUP = env_csv("ATOMIC_GROUP")
MERGE_OVERLOADS = env_bool("MERGE_OVERLOADS", False)
ISD_JSON_OUT = os.getenv("ISD_JSON_OUT")
MVSCAN_STRICT_CONFIG = env_bool("MVSCAN_STRICT_CONFIG", True)
MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS = env_bool("MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS", False)
MVSCAN_CONTEXTUAL_KEYS = env_bool("MVSCAN_CONTEXTUAL_KEYS", False)
MVSCAN_INTERFACE_DISPATCH = env_bool("MVSCAN_INTERFACE_DISPATCH", False)
MVSCAN_ROOT_CONTEXT_SINKS = env_bool("MVSCAN_ROOT_CONTEXT_SINKS", False)
MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK = env_int("MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK", default=128, minimum=1)
MVSCAN_MAX_DISPATCH_TARGETS = env_int("MVSCAN_MAX_DISPATCH_TARGETS", default=16, minimum=1)
_KNOWN_MVSCAN_ENV = {
    "MVSCAN_STRICT_CONFIG",
    "MVSCAN_ABLATION",
    "MVSCAN_INCLUDE_SCALAR_WITNESSES",
    "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS",
    "MVSCAN_CONTEXTUAL_KEYS",
    "MVSCAN_INTERFACE_DISPATCH",
    "MVSCAN_ROOT_CONTEXT_SINKS",
    "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK",
    "MVSCAN_MAX_DISPATCH_TARGETS",
}

### Value-influence sink test

# Optional second-stage reader gate. ICFG influence already establishes an
# omitted-member consumer witness; this bounded heuristic may prune further
# but proves neither feasibility nor exploitability.
SINK_TEST = env_enum("SINK_TEST", "none", {"none", "samevar", "value"})

# Per-process output registry to distinguish keys while keeping JSON uniform
_JSON_RUNS: dict[tuple[int, str], dict[str, dict]] = {}

@dataclass(frozen=True, slots=True)
class FindingWitnessRecord:
    """One fully context-qualified writer/reader witness before aggregation."""
    subject: object
    writer_bid: BasicBlock
    reader_bid: BasicBlock
    writer_owner: str
    writer_storage_context: str
    reader_owner: str
    reader_storage_context: str
    writer_file: str
    writer_line: int
    reader_file: str
    reader_line: int
    relation_evidence: tuple = ()
    written_members: frozenset = frozenset()
    sink_sites: tuple = ()
    writer_bindings: tuple[tuple[str, str], ...] = ()
    reader_bindings: tuple[tuple[str, str], ...] = ()
    writer_active_sender: str = ""
    reader_active_sender: str = ""
    writer_reaches_reader: bool = False
    reader_reaches_writer: bool = False

@dataclass(frozen=True, slots=True)
class CandidateKey:
    """Stable identity of one writer-centered MV-SI candidate."""
    writer_owner: str
    writer_bid: BasicBlock
    relation_id: tuple
    written_members: tuple
    potentially_stale_members: tuple

@dataclass
class CandidateAccumulator:
    """
    Evidence accumulated for one CandidateKey.
    ``key_constraints`` is a union; witness-local lists are authoritative and
    the candidate-wide set must not be interpreted as one conjunction.
    """
    relation: object
    context_instances: set = field(default_factory=set)
    writer_exposures: set = field(default_factory=set)
    reader_witnesses: set = field(default_factory=set)
    sink_sites: set = field(default_factory=set)
    call_paths: set = field(default_factory=set)
    key_constraints: set = field(default_factory=set)
    supporting_origins: set = field(default_factory=set)

# Derive a reproducible short identifier from a candidate's semantic key
def candidate_id(key: CandidateKey) -> str:
    payload = json.dumps({
        "writer_owner": key.writer_owner,
        "writer_bid": key.writer_bid,
        "relation_id": key.relation_id,
        "written_members": key.written_members,
        "potentially_stale_members": key.potentially_stale_members,
    }, sort_keys=True, separators=(",", ":")).encode()
    return sha256(payload).hexdigest()[:20]

# Reconstruct the shortest known root-to-writer call chain for a witness
def _shortest_call_chain(icfg, record):
    function_key_current = record.writer_bid[0]
    fn = icfg.fn_lookup.get(function_key_current)
    entry = attr(fn, "entry_point")
    if entry is None: return (record.writer_owner, function_key_current)
    target_bid = (function_key_current, entry.node_id)
    candidates = [
        (context, parent)
        for context in icfg.contexts_by_call_target.get(target_bid, set())
        if context.owner == record.writer_owner
        for parent in icfg.context_call_parents.get((target_bid, context), set())
    ]
    if not candidates: return (record.writer_owner, function_key_current)
    context, parent = min(candidates, key=repr)
    chain, seen = [function_key_current], set()
    while parent is not None:
        source_bid, caller_context = parent[0], parent[1]
        caller_key = source_bid[0]
        if caller_key in seen: break
        
        seen.add(caller_key)
        chain.append(caller_key)
        caller_fn = icfg.fn_lookup.get(caller_key)
        caller_entry = attr(caller_fn, "entry_point")
        if caller_entry is None: break
        parents = icfg.context_call_parents.get(((caller_key, caller_entry.node_id), caller_context), set())
        parent = min(parents, key=repr) if parents else None
    chain.reverse()
    if not chain or chain[0] != record.writer_owner:
        chain.insert(0, record.writer_owner)
    return tuple(chain)

# Serialize every detector option that can affect analysis results
def effective_config() -> dict:
    return {
        "MVSCAN_ABLATION": icfg_module.MVSCAN_ABLATION,
        "MVSCAN_INCLUDE_SCALAR_WITNESSES": icfg_module.INCLUDE_SCALAR_WITNESSES,
        "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS": MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS,
        "MVSCAN_CONTEXTUAL_KEYS": MVSCAN_CONTEXTUAL_KEYS,
        "MVSCAN_INTERFACE_DISPATCH": MVSCAN_INTERFACE_DISPATCH,
        "MVSCAN_ROOT_CONTEXT_SINKS": MVSCAN_ROOT_CONTEXT_SINKS,
        "MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK": MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK,
        "MVSCAN_MAX_DISPATCH_TARGETS": MVSCAN_MAX_DISPATCH_TARGETS,
        "DIVERGENCE_BUDGET": DIVERGENCE_BUDGET,
        "USER_CALLABLE_ALWAYS": sorted(USER_CALLABLE_ALWAYS),
        "USER_CALLABLE_DENY": sorted(USER_CALLABLE_DENY),
        "SINK_TEST": SINK_TEST,
        "ATOMIC_GROUP": sorted(ATOMIC_GROUP),
        "MERGE_OVERLOADS": MERGE_OVERLOADS,
        "NOOP_WRITE_FILTER": icfg_module.NOOP_WRITE_FILTER,
        "REQUIRE_SAME_SLOT_KEY": icfg_module.REQUIRE_SAME_SLOT_KEY,
        "MAPPING_MODE": icfg_module.MAPPING_MODE,
        "ENABLE_BRANCH_GROUPS": icfg_module.ENABLE_BRANCH_GROUPS,
        "ENABLE_MULTI_RETURN_GROUPS": icfg_module.ENABLE_MULTI_RETURN_GROUPS,
        "ENABLE_EXTERNAL_STATE": icfg_module.ENABLE_EXTERNAL_STATE,
    }

# Hash a source file when it exists, otherwise report no digest
def _sha256_file(p):
    if not p: return None
    file_path = Path(p)
    return sha256(file_path.read_bytes()).hexdigest() if file_path.is_file() else None

# Hash JSON-like data using deterministic key and separator ordering
def _structural_digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

# Describe the detector runtime and hashes of its implementation modules
def detector_metadata() -> dict:
    try: vers = importlib.metadata.version("slither-analyzer")
    except importlib.metadata.PackageNotFoundError: vers = None
    return {
        "name": "MV-Scan",
        "python_version": platform.python_version(),
        "slither_version": vers,
        "source_hashes": {
            "inconsistent_state": _sha256_file(__file__),
            "icfg": _sha256_file(icfg_module.__file__),
            "mvscan_env": _sha256_file(mvscan_env_module.__file__),
        },
    }

# Fingerprint compiler, source, and build-info inputs for reproducibility
def compilation_metadata(detector) -> dict:
    crytic_compile = attr(detector.compilation_unit, "crytic_compile")
    compiler_version = attr(crytic_compile, "compiler_version")
    source_paths = sorted({ source_file_key(contract) for contract in detector.compilation_unit.contracts })
    
    source_hasher = sha256()
    for source_path in source_paths:
        path = Path(source_path)
        source_hasher.update(source_path.encode())
        if path.is_file(): source_hasher.update(path.read_bytes())
    build_info_paths = sorted(Path("artifacts/build-info").glob("*.json"))
    
    build_hasher = sha256()
    for path in build_info_paths:
        build_hasher.update(path.name.encode())
        build_hasher.update(path.read_bytes())
    if compiler_version is None:
        versions = set()
        for path in build_info_paths:
            try: build_info = json.loads(path.read_text())
            except (OSError, ValueError): continue
            version = (build_info.get("solcLongVersion") or build_info.get("solcVersion"))
            if version: versions.add(str(version))
        if versions: compiler_version = ",".join(sorted(versions))
    return {
        "solidity_compiler_version": (str(compiler_version) if compiler_version is not None else None),
        "target_source_digest": source_hasher.hexdigest(),
        "build_info_digest": (build_hasher.hexdigest() if build_info_paths else None),
    }

# Identify detector instances that belong to the same Slither analysis run
def _analysis_run_token(detector) -> int:
    slither_obj = attr(detector, "slither")
    if slither_obj is not None: return id(slither_obj)
    crytic_compile = attr(detector.compilation_unit, "crytic_compile")
    if crytic_compile is not None: return id(crytic_compile)
    return id(detector.compilation_unit)

# Produce a stable id for a compilation unit's contract set
def _compilation_unit_id(unit) -> str:
    identities = sorted((source_file_key(contract), str(attr(contract, "canonical_name") or attr(contract, "name") or "<unknown-contract>")) for contract in unit.contracts)
    return sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest()[:20]

# Merge one compilation unit into the run-level JSON output atomically
def _record_json_unit(detector, unit_id, unit_stats, findings, relation_catalog=(), dispatch_catalog=()) -> None:
    if not ISD_JSON_OUT: return
    output_path = Path(ISD_JSON_OUT).resolve()
    run_key = (_analysis_run_token(detector), str(output_path))
    units = _JSON_RUNS.setdefault(run_key, {})
    units[unit_id] = {
        "unit_id": unit_id,
        "compilation_metadata": compilation_metadata(detector),
        "stats": dict(sorted(unit_stats.items())),
        "relations": list(relation_catalog),
        "calls": list(dispatch_catalog),
        "candidates": findings,
        "candidate_count": len(findings),
        "context_instance_count": sum(finding.get("context_instance_count", 0) for finding in findings),
        "reader_witness_count": sum(finding.get("reader_witness_count", 0) for finding in findings),
    }
    ordered_units = [units[key] for key in sorted(units)]
    document = {
        "detector": detector_metadata(),
        "effective_config": effective_config(),
        "candidate_count": sum(unit["candidate_count"] for unit in ordered_units),
        "context_instance_count": sum(unit["context_instance_count"] for unit in ordered_units),
        "reader_witness_count": sum(unit["reader_witness_count"] for unit in ordered_units),
        "compilation_units": ordered_units,
    }
    temporary_path = output_path.with_name(output_path.name + f".tmp.{os.getpid()}")
    with temporary_path.open("w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(temporary_path, output_path)

# get block id's reads and return if the var is in its reads
def block_reads_var(bid,icfg,var) -> bool:
    reads = (icfg.blocks.get(bid, {}).get("reads", set()))
    if var in reads: return True

    if isinstance(var, MappingSlotVar): return var.base in reads

    members = attr(var, "vars")
    if members is None: return False

    # Preferred exact relation provenance
    if (icfg.relation_reads.get(var, {}).get(bid, set())): return True

    member_set = set(members)
    return any(o in member_set or (isinstance(o,MappingSlotVar) and o.base in member_set) for o in reads)

# Optional bounded sink heuristic: a read is notable if its value/copies influences
# (a) control-flow at a branch predicate
# (b) arguments/eth value to an ext/internal call
# (c) RHS of a storage write to any storage var/slot
def value_influence_hits_sensitive_sink(var, start_bid, icfg, budget) -> bool:
    if budget == 0: return False

    # Same-node sink
    if is_critical_sink_bid(start_bid, icfg) and block_reads_var(start_bid, icfg, var): return True

    seen = {start_bid}
    q, steps = deque([start_bid]), 0
    unlimited = (budget is None)
    while q and (unlimited or steps < budget):
        cur = q.popleft()
        steps += 1
        node = node_of(cur, icfg)

        # Branch predicate uses the variable
        if node and is_branch_node(node) and block_reads_var(cur, icfg, var) and reachable_without_overwrite(icfg, start_bid, cur, var):
            return True

        # Any call in the block and the block reads the variable
        if node and any(isinstance(ir, (HighLevelCall, InternalCall)) for ir in attr(node, "irs", [])) and block_reads_var(cur, icfg, var) and reachable_without_overwrite(icfg, start_bid, cur, var):
            return True

        # Storage write in the block and the block reads the variable
        if node and (attr(node, "variables_written") or any(attr(ir, "lvalue") for ir in attr(node, "irs", []))) and block_reads_var(cur, icfg, var) and reachable_without_overwrite(icfg, start_bid, cur, var):
            return True

        for nxt in sorted(icfg.reachability_successors(cur), key=lambda bid: (str(bid[0]), int(bid[1]))):
            if nxt not in seen:
                seen.add(nxt); q.append(nxt)
    return False

# sink-test scheduler
def hits_sink(var, read_bid, icfg) -> bool:
    if SINK_TEST == "value": return value_influence_hits_sensitive_sink(var, read_bid, icfg, DIVERGENCE_BUDGET)
    if SINK_TEST == "samevar": return forward_slice_hits_sink_from(var, read_bid, icfg, DIVERGENCE_BUDGET)
    return True

### Helpers for classifying nodes/shapes

# Resolve a block id to its node
def node_of(bid, icfg): return icfg.node_lookup.get(bid) if bid in icfg.blocks else None

# Check whether a node is one of the control-flow sink types tracked by MV-Scan
def is_branch_node(node) -> bool: return (node.type in branch_types)

# (DivertScan §4.2.3) Keep reads that reach external-call sites called "critical sinks." Call destination contamination could cause divergence
def is_external_call_node(node, icfg) -> bool:
    if node is None: return False # Node must exist

    # Heuristic for "critical sink": an external (cross-contract) call or dynamic low-level call
    fn = icfg.fn_lookup.get(function_key(node.function))
    if fn is None: return False
    for callsite_id, ir in icfg_module.iter_call_sites(node):
        if isinstance(ir, HighLevelCall):
            targets = icfg.call_targets_by_site.get(callsite_id, ())
            if not targets: return True # dynamic or low-level call
            
            for target_function_key in targets:
                tg = icfg.fn_lookup.get(target_function_key)
                if tg is None or attr(tg, "contract_declarer") is not attr(fn, "contract_declarer"):
                    return True # resolved callee belongs to a different contract
    return False

# (§4.2.3 Extension) A block is a critical sink if it's a branch predicate or an external call site.
def is_critical_sink_bid(bid, icfg) -> bool:
    node = node_of(bid, icfg)
    if node is None: return False # node must exist
    return is_branch_node(node) or is_external_call_node(node, icfg)

# (§4.2.3 Extension) Budgeted forward slice from a read to see if the same var is re-read at a sink
def forward_slice_hits_sink_from(var, start_bid, icfg, budget=DIVERGENCE_BUDGET) -> bool:
    if budget == 0: return False # NO traversal
    if start_bid in icfg.var_reads.get(var, set()) and is_critical_sink_bid(start_bid, icfg): return True

    # Bounded forward slice along CFG from the first read of a var at a start-bid
    reads_of_var = icfg.var_reads.get(var, set())
    seen: set[BasicBlock] = {start_bid}
    q, steps = deque([start_bid]), 0
    unlimited = (budget is None)
    while q and (unlimited or steps < budget):
        cur = q.popleft()
        steps += 1

        # If we reach a re-read, that is notable! Otherwise keep going
        if cur in reads_of_var and is_critical_sink_bid(cur, icfg) and reachable_without_overwrite(icfg, start_bid, cur, var):
            return True
        for nxt in sorted(icfg.reachability_successors(cur), key=lambda bid: (str(bid[0]), int(bid[1]))):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False

### Variable id normalization for bucketing

def _stable_n(x) -> str: return str(attr(x, "canonical_name") or attr(x, "name") or x)

# Stable id used for bucketing, shape metadata, and deduplication
def var_key(v):
    # The relation members identify the exact branch/return relation site
    if isinstance(v, MultiVarGroup):
        return ("MVG", v.semantic_id)
    if isinstance(v, MappingSlotVar):
        return ("MS", source_file_key(v.base), _stable_n(v.base), str(v.key))
    if isinstance(v, ExternalStateVar):
        return ("EXT", str(v.addr), str(v.selector), tuple(v.args))
    return ("SV", source_file_key(v), _stable_n(v))

# (DivertScan's §4.2.1) Above-tx entry normalization that merges user-selected entry names
def normalize_entry_name(entry_name) -> str:
    if entry_name in ATOMIC_GROUP: return "ATOMIC_GROUP"

    # Converts Contract.fn(arg,. ..) => Contract.fn
    if MERGE_OVERLOADS:
        try:
            contract, rest = entry_name.split(".", 1)
            fn = rest.split("(", 1)[0].strip().strip("'\"")
            return f"{contract}.{fn}"
        except Exception:
            return entry_name
    return entry_name

# Hide Slither's temporary reference variables from user-facing relation names.
def prettify(v): return None if attr(v, "name", "").startswith("REF_") else attr(v, "name", "")

@dataclass(frozen=True, slots=True)
class RelationOrigin:
    """Physical dataflow origin of one inferred relation hypothesis."""
    origin_id: str
    function_key: str
    block_id: BasicBlock | None
    ir_index: int | None
    expression: str

# Convert relation provenance into its stable JSON representation
def serialize_rel_origin(o):
    return { "origin_id": o.origin_id, "function_key": o.function_key, "block_id": o.block_id, "ir_index": o.ir_index, "expression": o.expression }

class MultiVarGroup:
    """
    Origin-specific pseudo-entity representing one inferred relation.
    The pseudo indexes the union of member access sites for enumeration; a
    write to one member never means the whole relation was written.
    ``semantic_id`` preserves origins and ``equivalence_id`` groups equal
    member families for candidate aggregation.
    """
    __slots__ = ("vars", "semantic_id", "equivalence_id")

    # Store the relation members and its semantic and equivalence identities
    def __init__(self, vars_: tuple, semantic_id: tuple, equivalence_id: tuple):
        self.vars = vars_
        self.semantic_id = semantic_id
        self.equivalence_id = equivalence_id

    # Render a relation as a readable set of member names
    @property
    def name(self):
        return ("{" + ", ".join(sorted(filter(None, (prettify(member) for member in self.vars)))) + "}")

    # Hash the group and treat it as a statevar
    def __hash__(self): return hash(("MVG", self.semantic_id))

    # Check for equality between 2 grouping instances
    def __eq__(self, other):
        return (isinstance(other, MultiVarGroup) and self.semantic_id == other.semantic_id)

# Check whether an entity/relation has external contract state
def _contains_external_state(var) -> bool:
    if isinstance(var, ExternalStateVar): return True
    if isinstance(var, MultiVarGroup):
        return any(_contains_external_state(member) for member in var.vars)
    return False

# Determine whether accesses must share a deployment storage context
def _requires_same_storage_context(var) -> bool: return not _contains_external_state(var)

# Check whether a function summary includes >=2 relation members
def summary_covers_relation(summary, relation) -> bool:
    return all(
        any(location_matches_member(written_location, member) for written_location in summary.must_writes)
        for member in relation.vars
    )

### ICFG construction

def build_icfg(compilation_unit) -> ICFG:
    """
    Build one physical state-annotated ICFG for a compilation unit.
    Declared functions are materialized once; ordinary CFG successors remain
    separate from call-entry edges. External reachability and execution
    contexts are computed later by ``compute_entry_owners``.
    """
    icfg, functions_by_key = ICFG(), {}
    icfg.interface_dispatch_enabled = MVSCAN_INTERFACE_DISPATCH
    icfg.max_dispatch_targets = MVSCAN_MAX_DISPATCH_TARGETS
    
    # Register declarations while rejecting ambiguous canonical identities
    def register_function_or_modifier(fn):
        key = function_key(fn)
        existing = functions_by_key.get(key)
        if existing is not None and existing is not fn:
            raise RuntimeError(f"MV-Scan encountered two distinct declared functions/modifiers with the same canonical key: {key}")
        functions_by_key[key] = fn

    for contract in compilation_unit.contracts:
        for fn in contract.functions_and_modifiers_declared:
            register_function_or_modifier(fn)
    for fn in compilation_unit.functions:
        if attr(fn, "contract_declarer") is None:
            register_function_or_modifier(fn)
    functions = [functions_by_key[key] for key in sorted(functions_by_key)]
    
    # Index call targets and returned state locations before materializing blocks
    for fn in functions:
        icfg.fn_lookup[function_key(fn)] = fn
    icfg.build_resolver_indexes()
    icfg.precompute_return_summaries(functions)

    # Convert each Slither CFG node into the block facts consumed by MV-Scan.
    for fn in functions:
        for node in sorted(attr(fn, "nodes", []), key=lambda item: item.node_id):
            icfg.add_block(node)
    icfg.compute_relevant_formals()

    missing_call_sources = sorted( source for source in icfg.call_edges if source not in icfg.blocks )
    missing_call_targets = { source: sorted(target for target in targets if target not in icfg.blocks) for source, targets in icfg.call_edges.items() }
    missing_call_targets = { source: targets for source, targets in missing_call_targets.items() if targets }
    if missing_call_sources or missing_call_targets:
        raise RuntimeError(f"MV-Scan completed ICFG construction with invalid call edges: missing_sources={missing_call_sources}, missing_targets={missing_call_targets}")
    
    icfg.rebuild_predecessors()
    return icfg

### (DivertScan) §4.2.1 Entry reachability and user-callable heuristics

def is_user_callable(fn, contextual_ids=()) -> bool:
    """
    Return whether a function can seed a state-changing transaction root.
    Root mutability is read directly from Slither's Function.view and
    Function.pure properties. This root-only check is intentionally separate
    from the optional external static-call abstraction.
    """
    if (
        fn.visibility not in {"public", "external"}
        or attr(fn, "is_constructor", False)
        or bool_attr(fn, "view")
        or bool_attr(fn, "pure")
    ):
        return False
    candidate_ids = {function_key(fn), attr(fn, "full_name", ""), *contextual_ids}
    return not bool((candidate_ids - {""}) & USER_CALLABLE_DENY)

# Normalize Slither source paths for deterministic filtering/sorting
def norm_path(obj) -> str:
    normalized = str(source_file_key(obj)).replace("\\", "/").strip().lower()
    return "/" + normalized.lstrip("/")

# Return the explicit reason a contract cannot seed an external root.
def _root_contract_exclusion_reason(contract):
    if declaration_is_dependency(contract): return "dependency"
    if bool_attr(contract, "is_interface"): return "interface"
    if bool_attr(contract, "is_library"): return "library"
    if bool_attr(contract, "is_abstract"): return "abstract"
    return None

# Identify the externally callable deployment context
def _root_owner_key(contract, fn) -> str:
    contract_name = attr(contract, "canonical_name") or attr(contract, "name") or "<unknown-contract>"
    return f"{source_file_key(contract)}::{contract_name}.{fn.full_name}"

def compute_entry_owners(icfg: ICFG, compilation_unit):
    """
    Propagate external tx contexts over physical blocks
    * ICFG stores one physical implementation block rather than cloning it
    for every inherited exposure. Exposure names and deployment storage
    contexts are retained around one selected analysis-owner identity.
    * The outer owner, active storage domain, formal-key bindings, and active
    msg.sender are distinct. Internal/library calls preserve storage and
    sender; ordinary high-level calls switch storage and make the calling
    contract the callee's sender.
    """
    worklist, stats = deque(), defaultdict(int)
    entry_contexts = defaultdict(set)
    root_candidates: dict[BasicBlock, dict[str, dict]] = defaultdict(dict)

    icfg.entry_contexts_by_block.clear()
    icfg.root_function_by_owner.clear()
    icfg.root_exposures.clear()
    icfg.context_call_parents.clear()
    icfg.contexts_by_call_target.clear()

    contracts = sorted(attr(compilation_unit, "contracts", []) or [], key=lambda contract: (norm_path(contract), str(attr(contract, "canonical_name") or attr(contract, "name", ""))))

    # Phase 1: collect every eligible concrete exposure without seeding yet
    for contract in contracts:
        exclusion_reason = _root_contract_exclusion_reason(contract)
        entry_functions = list(attr(contract, "functions_entry_points") or attr(contract, "functions", []) or [])
        entry_functions.sort(key=lambda fn: (attr(fn, "full_name", ""), function_key(fn)))

        for fn in entry_functions:
            raw_exposure_owner = _root_owner_key(contract, fn)
            raw_implementation_owner = function_key(fn)

            exposure_owner = normalize_entry_name(raw_exposure_owner)
            implementation_owner = normalize_entry_name(raw_implementation_owner)
            force_ids = {
                raw_exposure_owner,
                raw_implementation_owner,
                attr(fn, "full_name", ""),
                exposure_owner,
                implementation_owner,
            }
            force_ids.discard("")

            force_included = bool(force_ids & USER_CALLABLE_ALWAYS)
            if not is_user_callable(fn, contextual_ids=(raw_exposure_owner, exposure_owner)):
                stats["rejected_non_callable"] += 1
                continue

            # Explicit USER_CALLABLE_ALWAYS may restore an otherwise excluded dependency/test context
            if (exclusion_reason is not None and not force_included):
                stats[f"excluded_{exclusion_reason}"] += 1
                continue

            entry_point = attr(fn, "entry_point")
            entry_bid = ((function_key(fn), entry_point.node_id) if entry_point is not None else None)
            if entry_bid is None:
                stats["missing_entry_point"] += 1
                continue
            if entry_bid not in icfg.blocks:
                stats["missing_entry_block"] += 1
                continue

            candidate = {
                "entry_bid": entry_bid,
                "exposure_owner": exposure_owner,
                "implementation_owner": implementation_owner,
                "force_included": force_included,
                "implementation_is_dependency": (declaration_is_dependency(fn)),
                "storage_context": icfg_module.contract_storage_key(contract),
                "root_function": fn,
            }

            # One candidate per contextual exposure
            if (exposure_owner not in root_candidates[entry_bid]):
                stats["eligible_exposures"] += 1

            root_candidates[entry_bid][exposure_owner] = candidate

    # 1. Explicitly forced exposure
    # 2. First-party implementation
    # 3. Stable lexical exposure ID
    # 4. Stable lexical implementation ID
    def candidate_sort_key(candidate):
        return (
            0 if candidate["force_included"] else 1,
            (0 if not candidate["implementation_is_dependency"] else 1),
            candidate["exposure_owner"],
            candidate["implementation_owner"],
        )

    # Phase 2: select 1 analysis owner per entry block
    for entry_bid in sorted(root_candidates, key=lambda bid: (str(bid[0]), int(bid[1]))):
        candidates = sorted(root_candidates[entry_bid].values(), key=candidate_sort_key)
        chosen = candidates[0]
        exposures = { candidate["exposure_owner"] for candidate in candidates }

        # Explicit force-inclusion should retain the explicitly selected id
        if chosen["force_included"] or chosen["implementation_is_dependency"]:
            analysis_owner = chosen["exposure_owner"]

        # For first-party inherited implementations, use the physical implementation id
        else:
            analysis_owner = chosen["implementation_owner"]

        icfg.root_exposures[analysis_owner].update(exposures)

        if len(exposures) > 1: stats["multi_exposure_entry_blocks"] += 1

        stats["collapsed_contextual_aliases"] += (len(candidates) - 1)

        # Deliberately retain Slither's exposure-specific root object:
        # Function summaries are built over physical declared functions. Slither may
        # provide a distinct inherited Function object for an exposure, so
        # owner-specific summary lookup can under-approximate some inherited roots.
        # MV-Scan accepts that completeness boundary rather than cloning summaries
        # across every inheritance context.
        root_function = chosen["root_function"]
        previous_root_function = icfg.root_function_by_owner.get(analysis_owner)
        if previous_root_function is not None and previous_root_function is not root_function:
            raise RuntimeError(f"One analysis owner resolved to multiple root functions: {analysis_owner}")
        icfg.root_function_by_owner[analysis_owner] = root_function

        storage_contexts = { candidate["storage_context"] for candidate in candidates }
        for storage_context in sorted(storage_contexts):
            if MVSCAN_CONTEXTUAL_KEYS:
                worklist.append((
                    entry_bid,
                    ExecutionContext(
                        owner=analysis_owner,
                        storage_context=storage_context,
                        bindings=root_context_bindings(root_function, analysis_owner),
                        active_sender=f"@sender::{analysis_owner}",
                    ),
                ))
            else:
                worklist.append((entry_bid, analysis_owner, storage_context))
        stats["seeded_contexts"] += len(storage_contexts)
        stats["seeded"] += 1

    # Phase 3: propagate the selected analysis owners and storage domains
    while worklist:
        item = worklist.popleft()
        if MVSCAN_CONTEXTUAL_KEYS:
            block_id, context = item
            owner = context.owner
            storage_context = context.storage_context
            execution_context = context
        else:
            block_id, owner, storage_context = item
            execution_context = (owner, storage_context)
        if block_id not in icfg.blocks: continue
        if execution_context in entry_contexts[block_id]: continue

        if MVSCAN_CONTEXTUAL_KEYS:
            context_group = {
                (existing.active_sender, existing.bindings)
                for existing in entry_contexts[block_id]
                if (existing.owner == owner and existing.storage_context == storage_context)
            }
            if (
                (execution_context.active_sender, execution_context.bindings) not in context_group
                and len(context_group) >= MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK
            ):
                raise RuntimeError(f"MV-Scan contextual key limit exceeded: block={block_id}, owner={owner}, storage_context={storage_context}, limit={MVSCAN_MAX_CONTEXTS_PER_OWNER_BLOCK}")

        entry_contexts[block_id].add(execution_context)
        # Ordinary CFG edges preserve the transaction root and deployed storage domain
        for successor in sorted(icfg.cfg_successors(block_id), key=lambda bid: (str(bid[0]), int(bid[1]))):
            if successor in icfg.blocks:
                if MVSCAN_CONTEXTUAL_KEYS: worklist.append((successor, execution_context))
                else: worklist.append((successor, owner, storage_context))

        # Call edges may preserve caller storage or switch to the callee deployment
        call_transitions = [
            (edge.target_bid, edge.storage_mode, edge.target_storage_context, edge)
            for edge in sorted(
                icfg.call_edges_by_source.get(block_id, set()),
                key=lambda edge: (str(edge.target_bid[0]), int(edge.target_bid[1]), edge.callsite_id[1]),
            )
        ]
        if not call_transitions:
            call_transitions = [
                (successor, *icfg.call_edge_context_modes.get((block_id, successor), ("preserve", None)))
                for successor in sorted(icfg.call_successors(block_id), key=lambda bid: (str(bid[0]), int(bid[1])))
            ]
        for transition in call_transitions:
            successor, mode, target_context = transition[:3]
            if successor not in icfg.blocks: continue
            if mode == "preserve": next_storage_context = storage_context
            elif mode == "switch": next_storage_context = target_context or "<unknown-storage-context>"
            else: raise RuntimeError(f"Unknown call-edge context mode: {mode}")
            if MVSCAN_CONTEXTUAL_KEYS:
                edge = transition[3] if len(transition) > 3 else None
                relevant = (
                    icfg.relevant_formals_by_function.get(edge.target_function_key, set())
                    if edge is not None else set()
                )
                next_context = ExecutionContext(
                    owner=owner,
                    storage_context=next_storage_context,
                    bindings=(compose_callee_bindings(execution_context, edge, relevant) if edge is not None else ()),
                    active_sender=(execution_context.active_sender if mode == "preserve" else f"@contract::{storage_context}"),
                )
                if edge is not None:
                    icfg.context_call_parents[(successor, next_context)].add((
                        edge.source_bid,
                        execution_context,
                        edge.callsite_id,
                        edge.target_function_key,
                    ))
                    icfg.contexts_by_call_target[successor].add(next_context)
                worklist.append((successor, next_context))
            else:
                worklist.append((successor, owner, next_storage_context))

    print(
        "[mvscan-stage] root-seeding-done "
        f"eligible_exposures={stats['eligible_exposures']} "
        f"seeded={stats['seeded']} "
        f"multi_exposure_entry_blocks={stats['multi_exposure_entry_blocks']} "
        f"collapsed_contextual_aliases={stats['collapsed_contextual_aliases']} "
        f"excluded_dependency={stats['excluded_dependency']} "
        f"excluded_interface={stats['excluded_interface']} "
        f"excluded_library={stats['excluded_library']} "
        f"excluded_abstract={stats['excluded_abstract']} "
        f"missing_entry_point={stats['missing_entry_point']} "
        f"missing_entry_block={stats['missing_entry_block']}",
        file=sys.stderr,
        flush=True,
    )

    icfg.entry_contexts_by_block.update({ block_id: set(contexts) for block_id, contexts in entry_contexts.items() })
    return {
        block_id: { (context.owner if isinstance(context, ExecutionContext) else context[0]) for context in contexts }
        for block_id, contexts in entry_contexts.items()
    }

# Intersect each variable: blocks set with the reachable blocks and drop any empties
# Keeps read/write maps consistent after pruning for reachability
def filter_bid_map(bid_map: dict[StateVariable, set[BasicBlock]], keep):
    for v in list(bid_map.keys()):
        bid_map[v].intersection_update(keep)
        if not bid_map[v]: del bid_map[v]

# Prune relation access sites to the set of reachable blocks.
def filter_relation_access_map(relation_map, keep):
    for relation in list(relation_map.keys()):
        accesses_by_block = (relation_map[relation])

        for block_id in list(accesses_by_block.keys()):
            if block_id not in keep: del accesses_by_block[block_id]

        if not accesses_by_block: del relation_map[relation]

# Helper to return (filename, first_line) for a (fn_name, node_id) block id
def src(bid, icfg):
    node = icfg.node_lookup.get(bid)
    source_mapping = attr(node, "source_mapping")
    if source_mapping is None: return "<unknown-source>", 0
    lines = list(attr(source_mapping, "lines", []) or [])
    return source_file_key(node), (min(lines) if lines else 0)

def fn_id(fn):
    """Return a stable Solidity signature and ordinary ABI selector."""
    contract = attr(attr(fn, "contract_declarer"), "name", "<unknown-contract>")
    signature = (
        attr(fn, "solidity_signature")
        or attr(fn, "full_name")
        or f"{attr(fn, 'name', '<unknown-function>')}("
        + ",".join(str(parameter.type) for parameter in (attr(fn, "parameters", []) or []))
        + ")"
    )
    pretty = f"{contract}.{signature}"
    has_selector = (
        attr(fn, "visibility") in {"public", "external"}
        and not bool_attr(fn, "is_constructor")
        and not bool_attr(fn, "is_fallback")
        and not bool_attr(fn, "is_receive")
    )
    selector = "0x" + keccak(text=signature)[:4].hex() if has_selector else None
    return pretty, selector

# Recursively convert detector values into deterministic JSON-compatible data
def _jsonable(value):
    if isinstance(value, tuple): return [_jsonable(item) for item in value]
    if isinstance(value, (frozenset, set)): return sorted((_jsonable(item) for item in value), key=str)
    return value

# Package a state entity's identity, location, and relation metadata for JSON
def var_meta(v, icfg):
    vname_prettified = prettify(v.base if isinstance(v, MappingSlotVar) else v) or v.name

    # Handle multi-variable group
    if isinstance(v, MultiVarGroup):
        return {
            "name": vname_prettified,
            "kind": "multi_var_group",
            "entity_key": _jsonable(var_key(v)),
            "members": [var_meta(member, icfg) for member in v.vars],
            "semantic_id": _jsonable(v.semantic_id),
            "origins": sorted(icfg.relation_origins.get(v, set())),
            "shadowed_base_members": [
                var_meta(member, icfg)
                for member in sorted(icfg.relation_shadowed_members.get(v, set()), key=var_key)
            ],
            "unresolved_base_read_count": sum(len(accesses) for accesses in icfg.relation_unresolved_base_reads.get(v, {}).values()),
            "unresolved_base_write_count": sum(len(accesses) for accesses in icfg.relation_unresolved_base_writes.get(v, {}).values()),
        }

    meta = {"name": vname_prettified, "entity_key": _jsonable(var_key(v))}
    if isinstance(v, ExternalStateVar): meta["kind"] = "external"
    elif isinstance(v, MappingSlotVar): meta.update({"kind": "mapping_slot", "key": v.key})
    else: meta["kind"] = "state"
    return meta

# Define deterministic ordering for witness records in reports
def witness_sort_key(record: FindingWitnessRecord) -> tuple:
    return (
        repr(attr(record.subject, "semantic_id", var_key(record.subject))),
        record.writer_owner, record.writer_storage_context,
        record.writer_active_sender,
        record.writer_bindings,
        str(record.writer_bid[0]), int(record.writer_bid[1]),
        record.reader_owner, record.reader_storage_context,
        record.reader_active_sender,
        record.reader_bindings,
        str(record.reader_bid[0]), int(record.reader_bid[1]),
        record.writer_file, record.writer_line,
        record.reader_file, record.reader_line,
        tuple(
            (
                state_entity_sort_key(evidence.writer_location),
                state_entity_sort_key(evidence.writer_member),
                state_entity_sort_key(evidence.reader_location),
                state_entity_sort_key(evidence.reader_member),
                tuple((constraint.left, constraint.right) for constraint in evidence.key_constraints),
            )
            for evidence in record.relation_evidence
        ),
        tuple((sink.block_id, sink.ir_index, sink.kind) for sink in record.sink_sites),
    )

# Convert one internal witness record into its stable report representation.
def _serialize_witness(record, subject_index, icfg):
    writer_sig, writer_selector = fn_id(icfg.fn_lookup[record.writer_bid[0]])
    reader_sig, reader_selector = fn_id(icfg.fn_lookup[record.reader_bid[0]])
    return {
        "subject_index": subject_index,
        "writer_reaches_reader": record.writer_reaches_reader,
        "reader_reaches_writer": record.reader_reaches_writer,
        "writer": {
            "context": {
                "owner": record.writer_owner,
                "storage_context": record.writer_storage_context,
                "bindings": list(record.writer_bindings),
                "active_sender": record.writer_active_sender,
            },
            "block": {
                "function_key": record.writer_bid[0],
                "node_id": record.writer_bid[1],
            },
            "signature": writer_sig,
            "selector": writer_selector,
            "file": record.writer_file,
            "line": record.writer_line,
        },
        "reader": {
            "context": {
                "owner": record.reader_owner,
                "storage_context": record.reader_storage_context,
                "bindings": list(record.reader_bindings),
                "active_sender": record.reader_active_sender,
            },
            "block": {
                "function_key": record.reader_bid[0],
                "node_id": record.reader_bid[1],
            },
            "signature": reader_sig,
            "selector": reader_selector,
            "file": record.reader_file,
            "line": record.reader_line,
        },
        "relation_evidence": [
            {
                "writer_location": var_meta(evidence.writer_location, icfg),
                "writer_member": var_meta(evidence.writer_member, icfg),
                "reader_location": var_meta(evidence.reader_location, icfg),
                "reader_member": var_meta(evidence.reader_member, icfg),
                "key_constraints": [{ "left": c.left, "right": c.right } for c in evidence.key_constraints],
            }
            for evidence in record.relation_evidence
        ],
        "sinks": [
            {
                "function_key": sink.block_id[0],
                "node_id": sink.block_id[1],
                "ir_index": sink.ir_index,
                "kind": sink.kind,
            }
            for sink in record.sink_sites
        ],
    }

class InconsistentState(AbstractDetector):
    """Slither entry point for MV-Scan candidate generation and validation."""

    ARGUMENT = 'inconsistent_state'
    HELP = 'Detect candidate multi-variable state inconsistencies'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.INFORMATIONAL

    WIKI = 'https://github.com/crytic/slither/wiki/Detector-Documentation'
    WIKI_TITLE = 'Multi-variable state inconsistency'
    WIKI_DESCRIPTION = (
        'Infers candidate relations among persistent state entities and reports '
        'writer transactions that update a proper subset before an omitted '
        'member is consumed by a modeled sensitive operation.'
    )
    WIKI_EXPLOIT_SCENARIO = (
        'A protocol maintains a relation among persistent entities. One '
        'transaction updates only part of it, and another consumes an omitted '
        'member in control, a storage write, or an external effect.'
    )
    WIKI_RECOMMENDATION = (
        'Review the inferred relation and ensure every transition preserves '
        'the protocol invariant before dependent state is consumed.'
    )

    """
    Detector pipeline
        (1) Compute storage layout for slot resolution
        (2) Build the ICFG (CFG, def-use, and metadata)
        (3) Create pseudo-variables:
            (a) Branch groups with >= 2 variables
            (b) Functions returning multiple variables
        (4) Build call graph edges (intra and inter-contract)
        (5) Determine user-callable entries and keep only reachable blocks
        (6) Prune the variable read/write maps to reachable nodes
        (7) Enumerate stale_read_pairs() and optionally gate by a sink heuristic (SINK_TEST=value|samevar|none)
        (8) Aggregate writer-centered candidates.
        (9) Emit Slither Output and reproducible machine-readable JSON.
    """
    def _detect(self) -> List[Output]:
        if MVSCAN_STRICT_CONFIG: reject_unknown_prefixed_environment("MVSCAN_", _KNOWN_MVSCAN_ENV)
        print("[mvscan-config] " + json.dumps(effective_config(), sort_keys=True), file=sys.stderr, flush=True)
        reset_icfg_analysis_caches()
        unit_id = _compilation_unit_id(self.compilation_unit)
        pair_stats = defaultdict(int)
        icfg = build_icfg(self.compilation_unit)
        print(f"[mvscan-stage] icfg-built blocks={len(icfg.blocks)} vars={len(icfg.var_writes)}", file=sys.stderr, flush=True)
        
        # Filter invalid members and prefer precise slots over mapping bases
        def normalize_relation_members(raw_members):
            eligible = set()
            for member in raw_members:
                pair_stats["relation_members_raw"] += 1
                if relation_member_is_eligible(member):
                    eligible.add(member)
                else:
                    pair_stats["relation_members_ineligible_filtered"] += 1
            exact_mapping_bases = {
                member.base for member in eligible
                if isinstance(member, MappingSlotVar)
            }
            shadowed = {
                member for member in eligible
                if isinstance(member, StateVariable)
                and member in exact_mapping_bases
            }
            return eligible - shadowed, shadowed

        # Intern one semantic multi-variable relation and record its accesses.
        def register_pseudo(raw_members, origin):
            if not raw_members: return None
            pair_stats["relation_origins_seen"] += 1
            logical_members, shadowed = normalize_relation_members(raw_members)
            pair_stats["relation_base_members_shadowed"] += len(shadowed)
            if len(logical_members) < 2:
                pair_stats["relation_origins_rejected_unary_after_shadowing"] += 1
                return None
            members = tuple(sorted(logical_members, key=var_key))
            equivalence_id = tuple(var_key(member) for member in members)
            semantic_id = (origin.origin_id, equivalence_id)
            pseudo = MultiVarGroup(members, semantic_id, equivalence_id)
            pair_stats["relation_origins_registered"] += 1
            icfg.relation_origins[pseudo].add(origin)
            icfg.relation_shadowed_members[pseudo].update(shadowed)

            # Classify access sites as exact, unresolved-base, or symbolic
            def register_access(entity, block_ids, exact_map, unresolved_map, template_map, aggregate_map):
                if isinstance(entity, MultiVarGroup): return
                if matching_relation_members(members, entity):
                    aggregate_map[pseudo].update(block_ids)
                    for block_id in block_ids:
                        exact_map[pseudo][block_id].add(entity)
                    return
                if MVSCAN_CONTEXTUAL_KEYS and isinstance(entity, MappingSlotVar):
                    same_base = {
                        member for member in members
                        if isinstance(member, MappingSlotVar)
                        and member.base == entity.base
                    }
                    if same_base and is_symbolic_key_template(entity.key):
                        aggregate_map[pseudo].update(block_ids)
                        for block_id in block_ids:
                            template_map[pseudo][block_id].add(entity)
                        pair_stats["relation_unbound_key_templates"] += len(block_ids)
                        return
                if entity in shadowed:
                    for block_id in block_ids:
                        unresolved_map[pseudo][block_id].add(entity)

            for entity, block_ids in list(icfg.var_reads.items()):
                register_access(
                    entity, block_ids, icfg.relation_reads,
                    icfg.relation_unresolved_base_reads,
                    icfg.relation_template_reads, icfg.var_reads,
                )
            for entity, block_ids in list(icfg.var_writes.items()):
                register_access(
                    entity, block_ids, icfg.relation_writes,
                    icfg.relation_unresolved_base_writes,
                    icfg.relation_template_writes, icfg.var_writes,
                )
            return pseudo

        entry_owners = compute_entry_owners(icfg, self.compilation_unit)
        keep = set(entry_owners)

        if ENABLE_MULTI_RETURN_GROUPS:
            for fn, return_sites in icfg.fn_return_sites.items():
                for return_site, returned_locations in return_sites.items():
                    if return_site.block_id not in keep:
                        pair_stats["relation_origins_rejected_unreachable"] += 1
                        continue
                    members = { location for location in returned_locations if relation_member_is_eligible(location) }
                    origin_id = (
                        f"return::{function_key(fn)}::"
                        f"{return_site.block_id[1]}::{return_site.ir_index}::"
                        f"{return_site.return_index}"
                    )
                    node = icfg.node_lookup.get(return_site.block_id)
                    expression = str(attr(node, "expression", "") or "")
                    register_pseudo(
                        members,
                        RelationOrigin(
                            origin_id=origin_id,
                            function_key=function_key(fn),
                            block_id=return_site.block_id,
                            ir_index=return_site.ir_index,
                            expression=expression,
                        ),
                    )

        # Restrict all later evidence to code reachable from an external transaction entry
        icfg.blocks = { block_id: info for block_id, info in icfg.blocks.items() if block_id in keep }
        icfg.rebuild_predecessors()
        filter_bid_map(icfg.var_reads, keep)
        filter_bid_map(icfg.var_writes, keep)
        for relation_map in (
            icfg.relation_reads,
            icfg.relation_writes,
            icfg.relation_unresolved_base_reads,
            icfg.relation_unresolved_base_writes,
            icfg.relation_template_reads,
            icfg.relation_template_writes,
        ):
            filter_relation_access_map(relation_map, keep)

        # Discover state values that can affect control, calls, writes, or returned state relations
        icfg.compute_sensitive_read_events(keep)
        if ENABLE_BRANCH_GROUPS:
            for sink_site, read_events in icfg.sink_reads_by_site.items():
                if sink_site.kind != "control": continue
                members = {
                    event.location for event in read_events
                    if relation_member_is_eligible(event.location)
                }
                sink_node = icfg.node_lookup.get(sink_site.block_id)
                sink_irs = (icfg_module._ssa_irs(sink_node) if sink_node is not None else [])
                sink_ir = (
                    sink_irs[sink_site.ir_index]
                    if 0 <= sink_site.ir_index < len(sink_irs)
                    else None
                )
                expression = str(attr(sink_node, "expression") or sink_ir or "")
                origin_id = (
                    f"sink::{sink_site.block_id[0]}::"
                    f"{sink_site.block_id[1]}::{sink_site.ir_index}"
                )
                register_pseudo(
                    members,
                    RelationOrigin(
                        origin_id=origin_id,
                        function_key=sink_site.block_id[0],
                        block_id=sink_site.block_id,
                        ir_index=sink_site.ir_index,
                        expression=expression,
                    ),
                )

        icfg.compute_function_write_summaries(keep)
        all_records, sink_cache = set(), {}

        # Memoize the configured sink predicate for repeated reader checks
        def reader_passes_sink(var, reader_bid):
            key = (var, reader_bid)
            if key not in sink_cache:
                sink_cache[key] = hits_sink(var, reader_bid, icfg)
            return sink_cache[key]

        # Expand static access pairs into concrete transaction-root and storage contexts
        for witness in stale_read_pairs(icfg, reader_filter=reader_passes_sink, pair_stats=pair_stats, contextual_relations=MVSCAN_CONTEXTUAL_KEYS):
            write_contexts = icfg.entry_contexts_by_block.get(witness.writer_bid, set())
            read_contexts = icfg.entry_contexts_by_block.get(witness.reader_bid, set())
            if not write_contexts or not read_contexts:
                raise RuntimeError("MV-Scan retained an access without an execution context")
            writer_file, writer_line = src(witness.writer_bid, icfg)
            reader_file, reader_line = src(witness.reader_bid, icfg)
            for raw_write_context in sorted(write_contexts):
                write_context = (
                    raw_write_context
                    if isinstance(raw_write_context, ExecutionContext)
                    else ExecutionContext(*raw_write_context)
                )
                for raw_read_context in sorted(read_contexts):
                    read_context = (
                        raw_read_context
                        if isinstance(raw_read_context, ExecutionContext)
                        else ExecutionContext(*raw_read_context)
                    )
                    pair_stats["owner_context_pairs_considered"] += 1
                    if (MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS and write_context.owner == read_context.owner):
                        pair_stats["same_outer_root_filtered"] += 1
                        continue
                    if (
                        _requires_same_storage_context(witness.variable)
                        and write_context.storage_context
                        != read_context.storage_context
                    ):
                        pair_stats["storage_context_mismatch"] += 1
                        continue
                    if (
                        MVSCAN_ROOT_CONTEXT_SINKS
                        and not icfg.read_event_is_sensitive(witness.reader_bid, witness.variable, read_context)
                    ):
                        pair_stats["root_context_sink_filtered"] += 1
                        continue

                    relation_evidence = witness.relation_evidence
                    if (MVSCAN_CONTEXTUAL_KEYS and isinstance(witness.variable, MultiVarGroup)):
                        relation_evidence = contextual_relation_access_evidence(
                            icfg,
                            witness.variable,
                            witness.writer_bid,
                            write_context,
                            witness.reader_bid,
                            read_context,
                        )
                        if not relation_evidence:
                            pair_stats["relation_context_incompatible"] += 1
                            continue

                    if isinstance(witness.variable, MultiVarGroup):
                        written_members = effective_relation_write_members(
                            icfg,
                            witness.variable,
                            witness.writer_bid,
                            write_context if MVSCAN_CONTEXTUAL_KEYS else None,
                        )
                        if not written_members or not written_members < frozenset(witness.variable.vars):
                            pair_stats["invalid_partial_write_filtered"] += 1
                            continue
                        omitted_members = frozenset(witness.variable.vars) - written_members
                        sensitive_events_by_member = sensitive_relation_member_events(icfg, witness.variable, witness.reader_bid, read_context)
                        supporting_events = {
                            event
                            for member in omitted_members
                            for event in sensitive_events_by_member.get(member, set())
                        }
                        if not supporting_events:
                            pair_stats["omitted_member_not_sensitive_filtered"] += 1
                            continue
                        relation_evidence = tuple(
                            evidence
                            for evidence in relation_evidence
                            if (
                                evidence.writer_member in written_members
                                and evidence.reader_member in omitted_members
                                and evidence.reader_member in sensitive_events_by_member
                            )
                        )
                        if not relation_evidence:
                            pair_stats["omitted_member_evidence_filtered"] += 1
                            continue
                        writer_root_fn = icfg.root_function_by_owner.get(write_context.owner)
                        write_sum = icfg.function_write_summaries.get(writer_root_fn)
                        if (write_sum is not None and summary_covers_relation(write_sum, witness.variable)):
                            pair_stats["must_full_relation_filtered"] += 1
                            continue

                    sink_events = (
                        supporting_events
                        if isinstance(witness.variable, MultiVarGroup)
                        else {
                            event
                            for event in icfg.sensitive_read_events_by_owner.get(read_context.owner, set())
                            if event.block_id == witness.reader_bid
                        }
                    )
                    sink_sites = {
                        sink_site
                        for event in sink_events
                        for sink_site in icfg.sink_sites_by_owner_and_event.get((read_context.owner, event), set())
                    }
                    if isinstance(witness.variable, MultiVarGroup):
                        relation_members = frozenset(witness.variable.vars)
                        assert written_members
                        assert written_members < relation_members
                        assert supporting_events
                        assert relation_evidence
                        assert all(
                            evidence.writer_member in written_members
                            and evidence.reader_member in relation_members - written_members
                            for evidence in relation_evidence
                        )
                    all_records.add(FindingWitnessRecord(
                        subject=witness.variable,
                        writer_bid=witness.writer_bid,
                        reader_bid=witness.reader_bid,
                        writer_owner=write_context.owner,
                        writer_storage_context=write_context.storage_context,
                        reader_owner=read_context.owner,
                        reader_storage_context=read_context.storage_context,
                        writer_file=writer_file,
                        writer_line=writer_line,
                        reader_file=reader_file,
                        reader_line=reader_line,
                        relation_evidence=relation_evidence,
                        written_members=written_members if isinstance(witness.variable, MultiVarGroup) else frozenset(),
                        sink_sites=tuple(sorted(sink_sites, key=lambda sink: (sink.block_id, sink.ir_index, sink.kind))),
                        writer_bindings=write_context.bindings,
                        reader_bindings=read_context.bindings,
                        writer_active_sender=write_context.active_sender,
                        reader_active_sender=read_context.active_sender,
                        writer_reaches_reader=witness.writer_reaches_reader,
                        reader_reaches_writer=witness.reader_reaches_writer,
                    ))
                    pair_stats["owner_context_pairs"] += 1

        # Collapse reader evidence around the writer that can leave relation members stale
        candidates = {}
        for record in sorted(all_records, key=witness_sort_key):
            relation = record.subject
            if not isinstance(relation, MultiVarGroup): continue
            written_members = record.written_members
            potentially_stale = set(relation.vars) - set(written_members)
            if not potentially_stale: continue
            key = CandidateKey(
                writer_owner=record.writer_owner,
                writer_bid=record.writer_bid,
                relation_id=relation.equivalence_id,
                written_members=tuple(sorted((var_key(member) for member in written_members), key=repr)),
                potentially_stale_members=tuple(sorted((var_key(member) for member in potentially_stale), key=repr)),
            )
            candidate = candidates.setdefault(key, CandidateAccumulator(relation=relation))
            candidate.context_instances.add((
                record.writer_owner,
                record.writer_storage_context,
                record.writer_active_sender,
                record.reader_owner,
                record.reader_storage_context,
                record.reader_active_sender,
                record.writer_bid,
                record.reader_bid,
            ))
            candidate.writer_exposures.add((
                record.writer_storage_context,
                tuple(sorted(icfg.root_exposures.get(record.writer_owner, set()))),
            ))
            candidate.reader_witnesses.add(record)
            candidate.sink_sites.update(record.sink_sites)
            candidate.call_paths.add(_shortest_call_chain(icfg, record))
            candidate.supporting_origins.update(icfg.relation_origins.get(relation, set()))
            for evidence in record.relation_evidence:
                candidate.key_constraints.update(evidence.key_constraints)

        json_candidates, results = [], []
        for key, candidate in sorted(candidates.items(), key=lambda item: candidate_id(item[0])):
            cid = candidate_id(key)
            relation = candidate.relation
            writer_file, writer_line = src(key.writer_bid, icfg)
            witnesses = sorted(candidate.reader_witnesses, key=witness_sort_key)

            json_candidates.append({
                "candidate_id": cid,
                "writer_owner": key.writer_owner,
                "writer_block": {
                    "function_key": key.writer_bid[0],
                    "node_id": key.writer_bid[1],
                    "file": writer_file,
                    "line": writer_line,
                },
                "relation": {
                    "members": [ var_meta(member, icfg) for member in relation.vars ]
                },
                "supporting_origin_sites": [
                    serialize_rel_origin(origin)
                    for origin in sorted(
                        candidate.supporting_origins,
                        key=lambda item: (
                            item.origin_id,
                            item.function_key,
                            repr(item.block_id),
                            item.ir_index if item.ir_index is not None else -1,
                        ),
                    )
                ],
                "written_members": list(key.written_members),
                "potentially_stale_members": list(key.potentially_stale_members),
                "context_instance_count": len(candidate.context_instances),
                "reader_witness_count": len(witnesses),
                "context_instances": [
                    {
                        "writer_owner": item[0],
                        "writer_storage_context": item[1],
                        "writer_active_sender": item[2],
                        "reader_owner": item[3],
                        "reader_storage_context": item[4],
                        "reader_active_sender": item[5],
                        "writer_bid": item[6],
                        "reader_bid": item[7],
                    }
                    for item in sorted(candidate.context_instances, key=repr)
                ],
                "reader_witnesses": [_serialize_witness(record, 0, icfg) for record in witnesses],
                "sink_sites": [
                    {
                        "function_key": sink.block_id[0],
                        "node_id": sink.block_id[1],
                        "ir_index": sink.ir_index,
                        "kind": sink.kind,
                    }
                    for sink in sorted(candidate.sink_sites, key=lambda sink: (sink.block_id, sink.ir_index, sink.kind))
                ],
                "call_paths": [list(path) for path in sorted(candidate.call_paths)],
                "key_equality_constraints": [
                    {"left": item.left, "right": item.right}
                    for item in sorted(candidate.key_constraints, key=lambda item: (item.left, item.right))
                ],
            })
            lines = [
                f"\n[MV-SI candidate {cid}] {relation.name}",
                f"\n writer root       -> {key.writer_owner}",
                f"\n writer effect     -> {writer_file}:{writer_line}",
                "\n written member    -> "
                + ", ".join(map(str, key.written_members)),
                "\n potentially stale -> "
                + ", ".join(map(str, key.potentially_stale_members)),
                f"\n reader witnesses  -> {len(witnesses)}",
                f"\n storage exposures -> {len(candidate.writer_exposures)}",
            ]
            results.append(self.generate_result(lines))

        pair_stats["candidate_count"] = len(json_candidates)
        pair_stats["context_instance_count"] = sum(len(candidate.context_instances) for candidate in candidates.values())
        pair_stats["reader_witness_count"] = sum(len(candidate.reader_witnesses) for candidate in candidates.values())
        if len(results) != len(json_candidates): raise RuntimeError("Candidate count mismatch!")

        accounted_contexts = (
            pair_stats["same_outer_root_filtered"]
            + pair_stats["storage_context_mismatch"]
            + pair_stats["root_context_sink_filtered"]
            + pair_stats["relation_context_incompatible"]
            + pair_stats["invalid_partial_write_filtered"]
            + pair_stats["omitted_member_not_sensitive_filtered"]
            + pair_stats["omitted_member_evidence_filtered"]
            + pair_stats["must_full_relation_filtered"]
            + pair_stats["owner_context_pairs"]
        )
        if accounted_contexts != pair_stats["owner_context_pairs_considered"]:
            raise RuntimeError(f"Owner-context accounting mismatch: considered={pair_stats['owner_context_pairs_considered']} accounted={accounted_contexts}")

        relation_catalog = []
        for relation in sorted(icfg.relation_origins, key=lambda item: repr(item.semantic_id)):
            relation_catalog.append({
                "relation_id": repr(relation.equivalence_id),
                "source_origins": [
                    serialize_rel_origin(origin)
                    for origin in sorted(
                        icfg.relation_origins[relation],
                        key=lambda item: (
                            item.origin_id, item.function_key,
                            repr(item.block_id),
                            item.ir_index if item.ir_index is not None else -1,
                        ),
                    )
                ],
                "members": [var_meta(member, icfg) for member in relation.vars],
                "shadowed_members": [
                    var_meta(member, icfg)
                    for member in sorted(icfg.relation_shadowed_members.get(relation, set()), key=var_key)
                ],
                "exact_read_blocks": len(icfg.relation_reads.get(relation, {})),
                "template_read_blocks": len(icfg.relation_template_reads.get(relation, {})),
                "exact_write_blocks": len(icfg.relation_writes.get(relation, {})),
                "template_write_blocks": len(icfg.relation_template_writes.get(relation, {})),
            })

        dispatch_catalog = [{
            "callsite": callsite,
            "targets": list(targets),
        } for callsite, targets in sorted(icfg.call_targets_by_site.items(), key=repr)]
        pair_stats["call_target_digest"] = _structural_digest(dispatch_catalog)
        pair_stats["execution_context_digest"] = _structural_digest([
            (
                block_id, (context.owner, context.storage_context, context.bindings, context.active_sender)
                if isinstance(context, ExecutionContext) else context,
            )
            for block_id, contexts in sorted(icfg.entry_contexts_by_block.items(), key=repr)
            for context in sorted(contexts)
        ])
        pair_stats["relation_digest"] = _structural_digest(relation_catalog)
        pair_stats["candidate_digest"] = _structural_digest(json_candidates)
        print("[mvscan-pairs] " + " ".join(f"{key}={pair_stats[key]}" for key in sorted(pair_stats)), file=sys.stderr, flush=True)
        _record_json_unit(self, unit_id, pair_stats, json_candidates, relation_catalog, dispatch_catalog)
        return results