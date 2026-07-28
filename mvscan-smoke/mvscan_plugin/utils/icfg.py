"""
icfg.py
Implementation of our state-annotated ICFG for MV-SCAN
"""
import os, re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Hashable, Set, Tuple
from slither.core.cfg.node import Node
from slither.core.variables.state_variable import StateVariable
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Call, Condition, EventCall, HighLevelCall, Index, InternalCall, LibraryCall, Member, OperationWithLValue, Phi, Return, SolidityCall, Unpack
from slither.slithir.variables import ReferenceVariable
from .alias import ALIAS_REG
from .mvscan_env import env_bool, env_enum

BasicBlock = Tuple[str, int]

# One concrete state-read occurrence
@dataclass(frozen=True, slots=True)
class ReadEvent:
    block_id: BasicBlock
    location: Hashable

# A value originating from one formal function parameter
@dataclass(frozen=True, slots=True)
class ParameterOrigin:
    index: int

Origin = ReadEvent | ParameterOrigin

@dataclass(frozen=True, slots=True)
class SinkSite:
    block_id: BasicBlock
    ir_index: int
    kind: str

@dataclass(slots=True)
class FunctionInfluenceSummary:
    # Formal params whose values can reach sensitive operations
    parameter_to_sink: set[int] = field(default_factory=set)

    # return index -> formal parameters affecting that return component
    parameter_to_returns: DefaultDict[int, set[int]] = field(default_factory=lambda: defaultdict(set))

    # Exact state-read events reaching sensitive operations.
    read_to_sink: set[ReadEvent] = field(default_factory=set)

    # return index -> exact state-read events affecting that component
    read_to_returns: DefaultDict[int, set[ReadEvent]] = field(default_factory=lambda: defaultdict(set))

    # Logical locations represented by each returned component, expressed in this function's parameter namespace
    return_locations: DefaultDict[int, set[Hashable]] = field(default_factory=lambda: defaultdict(set))

    sink_reads: DefaultDict[SinkSite, set[ReadEvent]] = field(default_factory=lambda: defaultdict(set))
    sink_parameters: DefaultDict[SinkSite, set[int]] = field(default_factory=lambda: defaultdict(set))

@dataclass(slots=True)
class FunctionWriteSummary:
    may_writes: set[Hashable] = field(default_factory=set)
    must_writes: set[Hashable] = field(default_factory=set)


_VALID_ABLATIONS = {
    "full",
    "sv_only",
    "no_branch_groups",
    "no_multi_return_groups",
    "no_external_state",
    "mapping_insensitive",
}

MVSCAN_ABLATION = env_enum("MVSCAN_ABLATION", "full", _VALID_ABLATIONS)

ENABLE_MULTIVAR_GROUPS = (
    MVSCAN_ABLATION != "sv_only"
)

# NOTE: toggling scalar witnesses prunes the search significantly (60-80%)
INCLUDE_SCALAR_WITNESSES = (
    MVSCAN_ABLATION == "sv_only"
    or env_bool("MVSCAN_INCLUDE_SCALAR_WITNESSES", False)
)

ENABLE_BRANCH_GROUPS = (
    MVSCAN_ABLATION
    not in {"sv_only", "no_branch_groups"}
)

ENABLE_MULTI_RETURN_GROUPS = (
    MVSCAN_ABLATION
    not in {"sv_only", "no_multi_return_groups"}
)

ENABLE_EXTERNAL_STATE = (
    MVSCAN_ABLATION != "no_external_state"
)

MAPPING_MODE = (
    "base_collapsed"
    if MVSCAN_ABLATION == "mapping_insensitive"
    else "precise"
)

# Only promote mapping base into the group when explicitly enabled (for ablation testing)
PROMOTE_MAPPING_BASE = env_bool("PROMOTE_MAPPING_BASE", False)

# external r/w classification tables
EXT_READS  = {"balanceof", "balanceof(address)", "totalsupply", "lastbalance"} if ENABLE_EXTERNAL_STATE else set()
EXT_WRITES = {"transfer", "transferfrom", "mint", "burn", "sync"} if ENABLE_EXTERNAL_STATE else set()

# storage var mapped to public getter selector
STORAGE_TO_SELECTOR = {
    "_lastBalance": "lastbalance",
    "balances":     "balanceof",
    "_balances":    "balanceof",
    "balanceOf":    "balanceof",
} if ENABLE_EXTERNAL_STATE else {}

### Ablation toggles

# Toggle that implements DivertScan's §4.2.3 P.4
NOOP_WRITE_FILTER = env_bool("NOOP_WRITE_FILTER", True)

# Require same mapping-slot key for r/w pairs when both sides use slots of the same base mapping
REQUIRE_SAME_SLOT_KEY = env_bool("REQUIRE_SAME_SLOT_KEY", True) and MAPPING_MODE == "precise"

### Helpers for mapping-key agreement

# Return { base_map_sv -> set(keys) } seen at a block for r/w
def slot_keys_at(icfg, bid, kind: str) -> dict:
    out = defaultdict(set)
    for v in icfg.blocks[bid][kind]:
        if isinstance(v, MappingSlotVar): out[v.base].add(v.key)
    return out

### Helpers to implement no-op from DivertScan

# Helper to normalize variable text
def norm_txt(s) -> str:
    t = re.sub(r"\baddress\((.+?)\)", r"\1", (s or "").replace("this.", ""))
    return t.replace(" ", "").lower()

def _non_ssa_variable(var): return getattr(var, "non_ssa_version", var)

def _formal_parameter_index(fn, operand):
    if fn is None or operand is None: return None
    concrete_operand = _non_ssa_variable(operand)
    parameters_ssa = list(getattr(fn, "parameters_ssa", []) or [])
    parameters = list(getattr(fn, "parameters", []) or [])
    parameter_count = max(len(parameters_ssa), len(parameters))

    for index in range(parameter_count):
        candidates = []
        if index < len(parameters_ssa):
            candidates.append(parameters_ssa[index])
        if index < len(parameters):
            candidates.append(parameters[index])

        for parameter in candidates:
            if operand is parameter: return index
            concrete_parameter = (
                _non_ssa_variable(parameter)
            )

            if concrete_operand is concrete_parameter:
                return index
            try:
                if concrete_operand == concrete_parameter: return index
            except Exception:
                pass
    return None

_PARAMETER_ALIAS_CACHE = {}


def reset_icfg_analysis_caches() -> None:
    _PARAMETER_ALIAS_CACHE.clear()
    ALIAS_REG.clear()

def canon_key(key, fn=None) -> str:
    parameter_index = _formal_parameter_index(fn, key)
    if parameter_index is not None: return f"$arg{parameter_index}"

    if fn is not None:
        aliases = _function_parameter_aliases(fn)
        parameter_indexes = set(aliases.get( key, set() ))
        parameter_indexes.update(aliases.get(_non_ssa_variable(key), set()))

        # A Phi value can represent multiple parameters
        if len(parameter_indexes) == 1:
            return (
                f"$arg"
                f"{next(iter(parameter_indexes))}"
            )

    return norm_txt(str(key))

def var_key_txt(v) -> str:
    t = norm_txt(str(getattr(v, "name", v)))
    return t if t and t != "none" else norm_txt(str(v))

# Collect simple SSA-style defs in this node
def build_defs_map(node):
    defs = {}
    for ir in getattr(node, "irs", []):
        if isinstance(ir, Assignment):
            lv, rv = norm_txt(str(getattr(ir, "lvalue", ""))), norm_txt(str(getattr(ir, "rvalue", "")))
            if lv: defs.setdefault(lv, rv)
    return defs

# Follow <= max_hops aliases inside the same node
def resolve_alias(txt, defs, max_hops=3) -> str:
    seen, cur = set(), txt
    for _ in range(max_hops):
        if cur in seen: break
        seen.add(cur)
        nxt = defs.get(cur)
        if not nxt: break
        cur = nxt
    return cur

# (DivertScan §4.2.3) Drop a pair w, r when the write sets v:=v or mapping slots like balances[a]:=balances[a].
def is_self_copy_write(v, node) -> bool:
    # Don't attempt on externals
    if type(v).__name__ == "ExternalStateVar": return False

    x, defs = var_key_txt(v), build_defs_map(node)
    found_write = False
    for ir in getattr(node, "irs", []):
        if not isinstance(ir, Assignment): continue
        lv, rv = norm_txt(str(getattr(ir, "lvalue", ""))), norm_txt(str(getattr(ir, "rvalue", "")))
        if lv != x: continue
        found_write = True
        if rv == x: continue
        if resolve_alias(rv, defs) == x: continue
        return False
    return found_write

# abstracts 1 concrete storage slot of a mapping/array (e.g. balances[addr] or prices[id])
class MappingSlotVar:
    __slots__ = ("base", "key")
    def __init__(self, base: StateVariable, key: str):
        self.base = base # StateVariable
        self.key = key # canonical key expression as a string

    def __hash__(self):
        return hash((self.base, self.key))

    def __eq__(self, other):
        return isinstance(other, MappingSlotVar) and self.base == other.base and self.key == other.key

    @property
    def name(self):
        return f"{self.base.name}[{self.key}]"

    def __str__(self):
        return self.name # @property
    __repr__ = __str__

# Match a concrete access location against one relation member
def location_matches_member(observed, expected) -> bool:
    if observed == expected: return True

    # Relation has an imprecise base mapping
    if (isinstance(expected, StateVariable) and isinstance(observed, MappingSlotVar) and observed.base == expected):
        return True
    return False


def matching_relation_members(members, observed) -> set:
    exact_matches = {member for member in members if observed == member}
    if exact_matches:
        return exact_matches
    return {
        member for member in members
        if (
            isinstance(member, StateVariable)
            and isinstance(observed, MappingSlotVar)
            and observed.base == member
        )
    }

# Return contract id
def contract_id(contract) -> str:
    return getattr(contract, "canonical_name", contract.name)

# Strip an outer entry
def outer_entry(full_name: str) -> str: return full_name # VU: [FIXED] Keep the function-level identity

# Detect constants or immutables
def is_const(v: StateVariable) -> bool: return getattr(v, "is_constant", False) or getattr(v, "is_immutable", False)

# Detect 32-byte role constants (e.g. DEFAULT_ADMIN)
def is_role_bytes32(v: StateVariable) -> bool:
    type_text = str(getattr(v, "type", "")).replace(" ", "").lower()
    return (type_text == "bytes32" and getattr(v, "name", "").endswith("_ROLE"))

# Detect if function can't write to storage
def is_view_only(fn) -> bool:
    if hasattr(fn, "state_mutability"): return fn.state_mutability in ("view", "pure") # >=0.9.3
    return getattr(fn, "is_view", False) or getattr(fn, "is_pure", False) # <=0.9.2

# Detect if any non-[view/pure] func in CU calls fn
# def called_from_stateful(fn, icfg):
#     for f in icfg.fn_lookup.values():
#         if is_view_only(f): continue
#         for n in f.nodes:
#             for ir in n.irs:
#                 if isinstance(ir, (HighLevelCall, InternalCall)) and ir.function == fn: return True
#     return False

# Treat any obj with variable_left/variable_right as a slot
def is_index_var(obj) -> bool:
    return hasattr(obj, "variable_left") and hasattr(obj, "variable_right")

# Makes a new mapping slot
def mk_slot(base, key, fn=None):
    if MAPPING_MODE == "base_collapsed": return base
    return MappingSlotVar(base, canon_key(key, fn))

# Replace $arg10 before $arg1
def _substitute_key_template(template, substitutions):
    instantiated = str(template)
    for placeholder in sorted(substitutions,key=len,reverse=True):
        instantiated = instantiated.replace(placeholder, substitutions[placeholder])
    return instantiated

# Convert the callee's positional key templates into key expressions meaningful inside the caller
def _call_key_substitutions(ir, caller_fn):
    arguments = list(getattr(ir, "arguments", []) or [])
    return { f"$arg{index}": canon_key(argument, caller_fn) for index, argument in enumerate(arguments)}

# Instantiate one abstract state location across a function call
def _instantiate_location_template(location, substitutions):
    if not isinstance(location, MappingSlotVar):
        return location
    instantiated_key = (
        _substitute_key_template(location.key, substitutions)
    )
    return mk_slot(location.base, instantiated_key)

# Instantiate a flattened callee return summary at one concrete call site
def _subst_returns_with_args(callee, ir, expr_vars, caller_fn):
    substitutions = (
        _call_key_substitutions(ir, caller_fn)
    )

    return { _instantiate_location_template( returned_location, substitutions ) for returned_location in expr_vars }

# wrapper so we can store <external selector> in the ICFG and still hash/compare it like a real StateVariable
class ExternalStateVar:
    __slots__ = ("selector", "addr", "args")
    def __init__(self, selector: str, addr: str | None, args=()):
        self.selector = selector.lower()
        self.addr = (addr or "unknown").lower()
        self.args = tuple(str(arg) for arg in args)

    @property
    def name(self) -> str: # for debugging / prints
        rendered_args = ", ".join(self.args)
        return f"{self.addr}.{self.selector}({rendered_args})"

    def __hash__(self):
        return hash((self.selector, self.addr, self.args))

    def __eq__(self, other):
        return (isinstance(other, ExternalStateVar)
            and self.selector == other.selector
            and self.addr == other.addr
            and self.args == other.args)

    def __str__(self):
        return f"EXT::{self.addr}::{self.selector}::{self.args}"
    __repr__ = __str__

# Return the real state variable represented by a relation entity
def relation_member_base(entity): return entity.base if isinstance(entity, MappingSlotVar) else entity

# A relation member must represent mutable protocol state
def relation_member_is_eligible(entity) -> bool:
    base = relation_member_base(entity)
    if isinstance(base, StateVariable):
        return not (is_const(base) or is_role_bytes32(base))

    # External state such as token.balanceOf is a valid relation member
    if isinstance(base, ExternalStateVar): return True
    return False

# 1 exact block-level state-interference witness
@dataclass(frozen=True, slots=True)
class RawStateWitness:
    writer_bid: BasicBlock
    reader_bid: BasicBlock
    variable: object
    operation_pattern: str

    # Intrafunctional ordering facts. Both are False for different functions.
    writer_reaches_reader: bool
    reader_reaches_writer: bool
    relation_evidence: tuple["RelationAccessEvidence", ...] = ()


@dataclass(frozen=True, slots=True)
class RelationAccessEvidence:
    writer_location: Hashable
    writer_member: Hashable
    reader_location: Hashable
    reader_member: Hashable
    writer_match_kind: str
    reader_match_kind: str

def basic_block_sort_key(bid: BasicBlock) -> tuple: return str(bid[0]), int(bid[1])

def state_entity_sort_key(var) -> tuple:
    if isinstance(var, MappingSlotVar):
        base = var.base
        base_name = (getattr(base, "canonical_name", None) or getattr(base, "name", None) or str(base))
        return ("mapping_slot", source_file_key(base), str(base_name), str(var.key))

    if isinstance(var, ExternalStateVar): return ("external", str(var.addr), str(var.selector), var.args)

    canonical_name = (getattr(var, "canonical_name", None) or getattr(var, "name", None) or str(var))
    return (type(var).__name__, source_file_key(var), str(canonical_name))

### Edits made during revision

# (1) Different contracts could contain functions with the same signature, so we fixate that here directly with two canonicalization methods

def source_file_key(obj) -> str:
    source_mapping = getattr(obj, "source_mapping", None)
    filename = getattr(source_mapping, "filename", None)
    return str(getattr(filename, "relative", None) or getattr(filename, "short", None) or getattr(filename, "absolute", None) or "<unknown-source>")

def contract_storage_key(contract) -> str:
    if contract is None: return "<unknown-storage-context>"
    canonical_name = (
        getattr(contract, "canonical_name", None)
        or getattr(contract, "name", None)
        or "<unknown-contract>"
    )
    return (f"{source_file_key(contract)}::{canonical_name}".replace("\\", "/").lower())

def function_key(fn) -> str:
    canonical_name = getattr(fn, "canonical_name", None)
    if not canonical_name:
        contract = getattr(fn, "contract_declarer", None)
        contract_name = (getattr(contract, "canonical_name", None) or getattr(contract, "name", None) or "<unknown-contract>")
        full_name = (getattr(fn, "full_name", None) or getattr(fn, "name", "<unknown-function>"))
        canonical_name = f"{contract_name}.{full_name}"
    return f"{source_file_key(fn)}::{canonical_name}"

# (2) callees could collide if A.snapshot is compared B.snapshot, e.g., so we canonicalize those as well

def resolve_unresolved_callee(ir, caller_fn, fn_lookup):
    raw_name = str(getattr(ir, "function_name", "") or "")
    bare_name = raw_name.split("(", 1)[0]
    candidates = [fn for fn in fn_lookup.values() if (getattr(fn, "name", None) == bare_name or getattr(fn, "full_name", None) == raw_name)]
    caller_contract = getattr(caller_fn, "contract_declarer", None)
    same_contract = [fn for fn in candidates if getattr(fn, "contract_declarer", None) is caller_contract]
    if len(same_contract) == 1: return same_contract[0]
    if len(candidates) == 1: return candidates[0]
    return None

#######
## Sensitive-read influence analysis

def _reference_origin(var):
    if not isinstance(var, ReferenceVariable): return None
    origin = getattr(var, "points_to_origin", None)
    if origin is None: origin = getattr(var, "points_to", None)
    return _non_ssa_variable(origin)

# Prefer SSA IR, retaining ordinary IR as a defensive fallback
def _ssa_irs(node):
    irs = list(getattr(node, "irs_ssa", []) or [])
    if irs: return irs
    return list(getattr(node, "irs", []) or [])

def _function_parameter_aliases(fn):
    cached = _PARAMETER_ALIAS_CACHE.get(fn)
    if cached is not None: return cached

    aliases = defaultdict(set)
    parameters_ssa = list(getattr(fn, "parameters_ssa", []) or [])
    parameters = list(getattr(fn, "parameters", []) or [])
    parameter_count = max(len(parameters_ssa), len(parameters))

    for index in range(parameter_count):
        candidates = []
        if index < len(parameters_ssa):
            candidates.append(parameters_ssa[index])

        if index < len(parameters):
            candidates.append(parameters[index])

        for parameter in candidates:
            aliases[parameter].add(index)
            aliases[_non_ssa_variable(parameter)].add(index)

    operations = [ir for node in getattr(fn, "nodes", []) for ir in _ssa_irs(node)]
    changed = True
    while changed:
        changed = False
        for ir in operations:
            if not isinstance(ir, (Assignment, Phi)): continue
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None: continue

            propagated = set()
            for operand in (getattr(ir, "read", []) or []):
                propagated.update(aliases.get(operand, set()))
                propagated.update(aliases.get(_non_ssa_variable(operand), set()))

            if not propagated: continue
            targets = { lvalue, _non_ssa_variable(lvalue) }
            for target in targets:
                before = len(aliases[target])
                aliases[target].update(propagated)
                if len(aliases[target]) != before: changed = True

    result = { variable: set(indexes) for variable, indexes in aliases.items() }
    _PARAMETER_ALIAS_CACHE[fn] = result
    return result

# Resolve SSA ReferenceVariables produced by Index operations to MappingSlotVar instances
def _function_reference_locations(fn, keep=None):
    locations, index_operations = {}, []
    for node in sorted(getattr(fn, "nodes", []), key=lambda item: item.node_id):
        bid = (function_key(fn), node.node_id)
        if keep is not None and bid not in keep: continue
        for ir in _ssa_irs(node):
            if isinstance(ir, Index): index_operations.append(ir)

    changed = True
    while changed:
        changed = False
        for ir in index_operations:
            base, key, location = ir.variable_left, ir.variable_right, None
            if isinstance(base, ReferenceVariable):
                previous = locations.get(base)
                if isinstance(previous, MappingSlotVar):
                    # base[first][second]
                    nested_key = (
                        f"{previous.key}]"
                        f"[{canon_key(key, fn)}"
                    )
                    location = MappingSlotVar(previous.base, nested_key)
                elif isinstance(previous, StateVariable):
                    location = mk_slot(previous, key, fn)
                else:
                    origin = _reference_origin(base)
                    if isinstance(origin, StateVariable): location = mk_slot(origin, key, fn)

            else:
                origin = _non_ssa_variable(base)
                if isinstance(origin, StateVariable): location = mk_slot(origin, key, fn)

            if location is None: continue
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None: continue

            if locations.get(lvalue) != location:
                locations[lvalue] = location
                changed = True

    return locations

def _is_mapping_state_variable(var) -> bool:
    if not isinstance(var, StateVariable): return False
    var_type = getattr(var, "type", None)
    type_name = type(var_type).__name__
    type_text = str(var_type).replace(" ", "").lower()
    return (type_name == "MappingType" or type_text.startswith("mapping("))

# Recover the exact persistent-storage locations read and written by 1 CFG block
def _node_storage_accesses(node, reference_locations):
    reads, writes, precise_read_bases, precise_write_bases = set(), set(),set(),set()
    unresolved_read_bases, unresolved_write_bases = set(), set()
    def record_read(location):
        if location is None: return

        reads.add(location)
        if isinstance(location, MappingSlotVar):
            precise_read_bases.add(location.base)
        elif _is_mapping_state_variable(location):
            unresolved_read_bases.add(location)

    def record_write(location):
        if location is None: return

        writes.add(location)
        if isinstance(location, MappingSlotVar):
            precise_write_bases.add(location.base)
        elif _is_mapping_state_variable(location):
            unresolved_write_bases.add(location)

    # Index constructs a storage reference
    for ir in _ssa_irs(node):
        if isinstance(ir, Index):
            key_operand = getattr(ir, "variable_right", None)
            if key_operand is not None:
                record_read(_location_of_read_operand(key_operand, reference_locations))
            continue

        # Member and Phi construct or merge values/references. The actual
        # storage read is recorded when their resulting reference/value is
        # consumed by a later operation.
        if isinstance(ir, (Member, Phi)): continue

        # Every state-backed operand consumed by this operation is a read at
        # this block.
        for operand in (getattr(ir, "read", []) or []):
            record_read(_location_of_read_operand(operand, reference_locations))

        # Persistent state lvalue
        if _is_storage_lvalue(ir):
            record_write(_location_of_read_operand(getattr(ir, "lvalue", None), reference_locations))

    return (reads, writes, precise_read_bases, precise_write_bases, unresolved_read_bases, unresolved_write_bases)

# Convert an SSA operand into an abstract state location
def _location_of_read_operand(operand, reference_locations):
    if isinstance(operand, ReferenceVariable):
        location = reference_locations.get(operand)
        if location is not None: return location
        origin = _reference_origin(operand)
        if isinstance(origin, StateVariable): return origin
        return None
    concrete = _non_ssa_variable(operand)
    if isinstance(concrete, StateVariable): return concrete
    return None

# Return all origins reaching an SSA operand, including a new ReadEvent when the operand directly reads state
def _origins_for_operand( operand, bid, origins, reference_locations):
    result = set(origins.get(operand, set()))
    location = _location_of_read_operand(operand, reference_locations)
    if location is not None: result.add(ReadEvent(bid, location))
    return result

# Return whether the operation writes persistent Solidity storage
def _is_storage_lvalue(ir) -> bool:
    if not isinstance(ir, OperationWithLValue): return False

    # These create references/SSA joins but do not themselves perform persistent storage writes
    if isinstance(ir, (Index, Member, Phi)): return False

    lvalue = getattr(ir, "lvalue", None)
    if lvalue is None: return False

    concrete = _non_ssa_variable(lvalue)
    if isinstance(concrete, StateVariable): return True

    if isinstance(lvalue, ReferenceVariable):
        return isinstance(_reference_origin(lvalue), StateVariable)
    return bool(getattr(lvalue, "is_storage", False))

# Capture require/assert even where Slither represents them as a SolidityCall rather than a separate Condition operation
def _is_control_solidity_call(ir) -> bool:
    if not isinstance(ir, SolidityCall): return False
    function_text = str(getattr(ir, "function", "")).lower()
    return ( "require(" in function_text or "assert(" in function_text )

# Internal and library calls are handled through function summaries
def _is_external_effect(ir) -> bool:
    if isinstance(ir, (InternalCall, LibraryCall, EventCall)): return False
    if isinstance(ir, SolidityCall):
        function_text = str(getattr(ir, "function", "")).lower()
        return ("selfdestruct" in function_text or "suicide" in function_text)
    return isinstance(ir, Call)

# Sensitive operations are: branch/control predicates; persistent storage writes; external interactions
def _is_sensitive_operation(ir) -> bool:
    return (isinstance(ir, Condition) or _is_control_solidity_call(ir) or _is_storage_lvalue(ir) or _is_external_effect(ir))

def _sensitive_operation_kind(ir) -> str | None:
    if isinstance(ir, Condition) or _is_control_solidity_call(ir):
        return "control"
    if _is_storage_lvalue(ir):
        return "storage_write"
    if _is_external_effect(ir):
        return "external_effect"
    return None

def _return_values(ir):
    values = getattr(ir, "values", None)
    if values is None: values = getattr(ir, "read", []) or []
    return list(values)

# Obtain the tuple variable consumed by an Unpack operation
def _unpack_source(ir):
    for attribute in ("tuple", "tuple_variable", "variable"):
        value = getattr(ir, attribute, None)
        if value is not None: return value

    reads = list(getattr(ir, "read", []) or [])
    return reads[0] if reads else None

def _merge_origin_set(mapping, key, values) -> bool:
    if key is None or not values: return False
    before = len(mapping[key])
    mapping[key].update(values)
    return len(mapping[key]) != before

# Compute a function summary using exact origin propagation
def _analyze_function_influence(fn, keep, summaries) -> FunctionInfluenceSummary:
    origins: DefaultDict[object, set[Origin]] = defaultdict(set)

    # Tuple-return variable -> return index -> origins
    tuple_components: DefaultDict[object, DefaultDict[int, set[Origin]]] = defaultdict(lambda: defaultdict(set))
    sensitive_origins: set[Origin] = set()
    sink_origins: DefaultDict[SinkSite, set[Origin]] = defaultdict(set)
    return_origins: DefaultDict[int, set[Origin]] = defaultdict(set)

    # SSA value -> logical state locations represented by that value
    value_locations: DefaultDict[object, set[Hashable]] = defaultdict(set)

    # Tuple SSA value -> return component -> logical locations
    tuple_location_components: DefaultDict[object, DefaultDict[int, set[Hashable]]] = defaultdict(lambda: defaultdict(set))

    # Function return index -> logical locations
    returned_locations: DefaultDict[int, set[Hashable]] = defaultdict(set)

    parameters = list(getattr(fn, "parameters_ssa", []) or [])

    if not parameters:
        parameters = list(getattr(fn, "parameters", []) or [])

    for index, parameter in enumerate(parameters):
        origins[parameter].add(ParameterOrigin(index))

    reference_locations = _function_reference_locations(fn, keep)
    operations = []
    for node in sorted(getattr(fn, "nodes", []), key=lambda item: item.node_id):
        bid = (function_key(fn), node.node_id)
        if ( keep is not None and bid not in keep ):
            continue
        for ir_index, ir in enumerate(_ssa_irs(node)):
            operations.append((bid, ir_index, ir))

    # SSA is usually already ordered, but Phi nodes and recursive summary propagation require a local fixed point
    local_changed = True
    while local_changed:
        local_changed = False
        for bid, ir_index, ir in operations:
            lvalue = getattr(ir, "lvalue", None)

            # Index and Member construct references
            if isinstance(ir, Index):
                structural_origins = set()
                key_operand = getattr(ir, "variable_right", None)
                if key_operand is not None:
                    structural_origins.update(_origins_for_operand(key_operand, bid, origins, reference_locations))
                
                base_operand = getattr(ir, "variable_left", None)
                if base_operand is not None:
                    # Only propagate pre-existing origins from the base reference
                    structural_origins.update(origins.get(base_operand, set()))

                if _merge_origin_set(origins, lvalue, structural_origins): local_changed = True
                continue

            if isinstance(ir, Member):
                structural_origins = set()
                for operand in getattr(ir, "read", []) or []:
                    structural_origins.update(origins.get(operand, set()))
                if _merge_origin_set(origins, lvalue, structural_origins):
                    local_changed = True
                continue

            read_origins = set()
            for operand in getattr(ir, "read", []) or []:
                read_origins.update(_origins_for_operand(operand, bid, origins, reference_locations))

            read_locations = set()

            for operand in getattr(ir, "read", []) or []:
                read_locations.update(value_locations.get(operand,set()))
                direct_location = (_location_of_read_operand(operand, reference_locations))

                if direct_location is not None:
                    read_locations.add(direct_location)

            # Instantiate summaries for all statically resolved calls
            # Internal/library calls are propagation boundaries only.
            # High-level calls are both external-interaction sinks; and summary-bearing return producers when their implementation is known
            if isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
                arguments = list(getattr(ir, "arguments", []) or [])
                argument_origins = [_origins_for_operand(argument, bid, origins, reference_locations) for argument in arguments]

                argument_locations = []
                for argument in arguments:
                    locations = set(value_locations.get(argument, set()))
                    locations.update(value_locations.get(_non_ssa_variable(argument), set()))
                    direct_location = (
                        _location_of_read_operand(argument,reference_locations)
                    )

                    if direct_location is not None:
                        locations.add(direct_location)

                    argument_locations.append(locations)

                call_key_substitutions = (
                    _call_key_substitutions(ir, fn)
                )
                callee = getattr(ir, "function", None)
                callee_summary = summaries.get(callee)
                internal_dispatch = isinstance(ir, (InternalCall, LibraryCall))
                if callee_summary is None:
                    if internal_dispatch:
                        # Unresolved internal/library dispatch: preserve recall
                        for values in argument_origins: sensitive_origins.update(values)
                        continue
                else:
                    callee_sites = (
                        set(callee_summary.sink_reads)
                        | set(callee_summary.sink_parameters)
                    )
                    for sink_site in callee_sites:
                        sink_origins[sink_site].update(
                            callee_summary.sink_reads.get(sink_site, set())
                        )
                        for parameter_index in callee_summary.sink_parameters.get(sink_site, set()):
                            if parameter_index < len(argument_origins):
                                sink_origins[sink_site].update(argument_origins[parameter_index])

                    # Reads inside the callee that reach a callee sink.
                    sensitive_origins.update(callee_summary.read_to_sink)

                    # Caller arguments reaching sensitive callee parameters
                    for parameter_index in (callee_summary.parameter_to_sink):
                        if parameter_index < len(argument_origins):
                            sensitive_origins.update(argument_origins[parameter_index])

                    all_return_indices = (set(callee_summary.read_to_returns) | set(callee_summary.parameter_to_returns) | set(callee_summary.return_locations))

                    all_return_origins = set()
                    all_return_locations = set()
                    for return_index in sorted(all_return_indices):
                        # Physical reads remain expressed in the callee's own namespace.
                        component_origins = set(
                            callee_summary.read_to_returns.get(return_index,set())
                        )

                        # Logical returned locations are translated into the caller's namespace
                        component_locations = {
                            _instantiate_location_template(
                                location,
                                call_key_substitutions,
                            )
                            for location in (
                                callee_summary.return_locations.get(return_index, set())
                            )
                        }

                        for parameter_index in (callee_summary.parameter_to_returns.get(return_index, set())):
                            if parameter_index < len(argument_origins):
                                component_origins.update(argument_origins[parameter_index])
                                component_locations.update(argument_locations[parameter_index])

                        if (not component_origins and not component_locations):
                            continue

                        all_return_origins.update(component_origins)
                        all_return_locations.update(component_locations)

                        if lvalue is not None:
                            if _merge_origin_set(tuple_components[lvalue], return_index, component_origins):
                                local_changed = True
                            if _merge_origin_set(tuple_location_components[lvalue], return_index, component_locations):
                                local_changed = True

                    if _merge_origin_set(origins, lvalue, all_return_origins):
                        local_changed = True
                    if _merge_origin_set(value_locations, lvalue, all_return_locations):
                        local_changed = True

                    if internal_dispatch: continue

            # Preserve individual return-component precision
            if isinstance(ir, Unpack):
                tuple_source = _unpack_source(ir)
                return_index = getattr(ir, "index", None)

                selected_origins = set()
                selected_locations = set()

                if (tuple_source is not None and return_index is not None):
                    selected_origins.update(
                        tuple_components[tuple_source].get(return_index, set())
                    )

                    selected_locations.update(
                        tuple_location_components[tuple_source].get(return_index, set())
                    )

                if (not selected_origins and tuple_source is not None):
                    selected_origins.update(origins.get(tuple_source, set()))

                if (not selected_locations and tuple_source is not None):
                    selected_locations.update(value_locations.get(tuple_source, set()))

                if _merge_origin_set(origins, lvalue, selected_origins):
                    local_changed = True

                if _merge_origin_set(value_locations, lvalue, selected_locations):
                    local_changed = True

                continue

            # An external getter produces an external-state read event whose value originates at the call's lvalue
            external_getter_origins = set()
            external_getter_locations = set()
            if isinstance(ir, HighLevelCall):
                selector = str(getattr(ir, "function_name", "")).split("(", 1)[0].lower()

                if selector in EXT_READS:
                    destination = getattr(ir, "destination", None)
                    address = getattr(destination, "canonical_name", getattr(destination, "name", None))
                    canonical_args = tuple(
                        canon_key(argument, fn)
                        for argument in (getattr(ir, "arguments", []) or [])
                    )
                    external_location = ExternalStateVar(selector, address, canonical_args)
                    external_getter_origins.add(ReadEvent(bid,external_location))
                    external_getter_locations.add(external_location)

            # Branches, storage writes and external interactions consume all value origins reaching their input operands
            sink_kind = _sensitive_operation_kind(ir)
            if sink_kind is not None:
                sink_site = SinkSite(block_id=bid, ir_index=ir_index, kind=sink_kind)
                sink_origins[sink_site].update(read_origins)
                sensitive_origins.update(read_origins)

            # A return propagates its origins into the matching return slot
            if isinstance(ir, Return):
                for return_index, value in enumerate(_return_values(ir)):
                    value_origins = (
                        _origins_for_operand(
                            value,
                            bid,
                            origins,
                            reference_locations,
                        )
                    )

                    return_origins[return_index].update(value_origins)
                    logical_locations = set(value_locations.get(value, set()))

                    direct_location = (
                        _location_of_read_operand(value, reference_locations)
                    )

                    if direct_location is not None:
                        logical_locations.add(direct_location)

                    returned_locations[return_index].update(logical_locations)

            # External getter return values begin at the call lvalue
            if external_getter_origins:
                if _merge_origin_set(origins, lvalue, external_getter_origins):
                    local_changed = True

            if external_getter_locations:
                if _merge_origin_set(value_locations,lvalue,external_getter_locations):
                    local_changed = True

            # Ordinary SSA definition: result = operation(inputs) propagates every input origin into result
            # Do not apply this rule to Call operations as call returns don't always depend on all call arguments
            if (isinstance(ir, OperationWithLValue) and not _is_storage_lvalue(ir) and (not isinstance(ir, Call) or isinstance(ir, SolidityCall)) and not isinstance(ir, Unpack)):
                if _merge_origin_set(origins, lvalue, read_origins):
                    local_changed = True
                if _merge_origin_set(value_locations, lvalue, read_locations):
                    local_changed = True

    summary = FunctionInfluenceSummary()
    for sink_site, origins_here in sink_origins.items():
        for origin in origins_here:
            if isinstance(origin, ReadEvent):
                summary.sink_reads[sink_site].add(origin)
            elif isinstance(origin, ParameterOrigin):
                summary.sink_parameters[sink_site].add(origin.index)
    for origin in sensitive_origins:
        if isinstance(origin, ReadEvent):
            summary.read_to_sink.add(origin)

        elif isinstance(origin, ParameterOrigin):
            summary.parameter_to_sink.add(origin.index)

    for return_index, component_origins in (return_origins.items()):
        for origin in component_origins:
            if isinstance(origin, ReadEvent):
                summary.read_to_returns[return_index].add(origin)

            elif isinstance(origin, ParameterOrigin):
                summary.parameter_to_returns[return_index].add(origin.index)

    for (return_index, locations) in returned_locations.items():
        summary.return_locations[return_index].update(locations)

    return summary

def _merge_function_summary(destination, source) -> bool:
    changed = False
    before = len(destination.parameter_to_sink)
    destination.parameter_to_sink.update(source.parameter_to_sink)
    changed |= (len(destination.parameter_to_sink) != before)
    before = len(destination.read_to_sink)
    destination.read_to_sink.update(source.read_to_sink)
    changed |= len(destination.read_to_sink) != before

    for sink_site, events in source.sink_reads.items():
        before = len(destination.sink_reads[sink_site])
        destination.sink_reads[sink_site].update(events)
        changed |= len(destination.sink_reads[sink_site]) != before
    for sink_site, parameter_indexes in source.sink_parameters.items():
        before = len(destination.sink_parameters[sink_site])
        destination.sink_parameters[sink_site].update(parameter_indexes)
        changed |= len(destination.sink_parameters[sink_site]) != before

    for return_index, parameter_indexes in (source.parameter_to_returns.items()):
        before = len(destination.parameter_to_returns[return_index])
        destination.parameter_to_returns[return_index].update(parameter_indexes)
        changed |= (len(destination.parameter_to_returns[return_index]) != before)

    for return_index, events in (source.read_to_returns.items()):
        before = len(destination.read_to_returns[return_index])
        destination.read_to_returns[return_index].update(events)
        changed |= (len(destination.read_to_returns[return_index]) != before)

    for (return_index, locations) in source.return_locations.items():
        before = len(destination.return_locations[return_index])
        destination.return_locations[return_index].update(locations)

        if (len(destination.return_locations[return_index]) != before):
            changed = True

    return changed

def _compute_function_influence_summaries(functions, keep=None):
    summaries = { fn: FunctionInfluenceSummary() for fn in functions }
    changed, rounds = True, 0
    maximum_rounds = max(32, (len(functions) * 8) + 8)
    while changed:
        changed = False
        rounds += 1
        if rounds > maximum_rounds:
            raise RuntimeError(f"MV-Scan function influence analysis did not converge after {maximum_rounds} rounds")

        for fn in functions:
            candidate = (_analyze_function_influence(fn, keep, summaries))
            if _merge_function_summary(summaries[fn], candidate):
                changed = True
    return summaries

#######

# Minimal ICFG where blocks[bid] maps to r/w/succ and var_reads/writes map to blocks where bid is read/write
class ICFG:
    def __init__(self):
        self.blocks: Dict[BasicBlock, Dict[str, Set]] = {}
        self.var_reads: Dict[StateVariable, Set[BasicBlock]] = defaultdict(set)
        self.var_writes: Dict[StateVariable, Set[BasicBlock]] = defaultdict(set)
        self.fn_lookup = {}  # function_key(fn) -> Function
        self.branch_groups: Dict[Hashable, Set] = defaultdict(set)
        self.var_to_branchgroups: Dict[object, Set[Hashable]] = defaultdict(set)
        self.fn_returns = {} # Function -> Set[Var]

        # Function -> return index -> exact state
        # locations influencing that returned component.
        self.fn_return_components: Dict[object, Dict[int, Set[object]]] = {}

        self.predecessors: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)
        self.node_lookup: Dict[BasicBlock, Node] = {}

        # Intraprocedural edges remain in blocks[bid]["succ"]
        # Interprocedural calls are stored separately to prevent context-insensitive wrong-caller return edges
        self.call_edges: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)
        self.call_edge_context_modes = {}
        self.call_predecessors: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)

        self.function_influence_summaries: dict[object, FunctionInfluenceSummary] = {}
        self.sensitive_read_events: set[ReadEvent] = set()
        self.sensitive_locations_by_block: DefaultDict[BasicBlock, set[Hashable]] = defaultdict(set)
        self.sink_reads_by_site: DefaultDict[SinkSite, set[ReadEvent]] = defaultdict(set)
        self.function_write_summaries = {}

        # Root-seeding metadata: each physical entry block receives one analysis owner
        self.root_owner_by_entry: Dict[BasicBlock, str] = {}
        self.root_exposures: DefaultDict[str, Set[str]] = defaultdict(set)

        # Reference locations are function-local and independent of root ownership
        self.reference_locations_by_function: Dict[str, Dict[object, object]] = {}

        # Relation pseudo -> block -> exact concrete
        # relation-member locations accessed at that block.
        self.relation_reads: DefaultDict[
            object,
            DefaultDict[BasicBlock, Set[object]],
        ] = defaultdict(lambda: defaultdict(set))

        self.relation_writes: DefaultDict[
            object,
            DefaultDict[BasicBlock, Set[object]],
        ] = defaultdict(lambda: defaultdict(set))

        self.relation_shadowed_members = defaultdict(set)
        self.relation_unresolved_base_reads = defaultdict(
            lambda: defaultdict(set)
        )
        self.relation_unresolved_base_writes = defaultdict(
            lambda: defaultdict(set)
        )

        # Storing all provenance sites
        self.relation_origins: DefaultDict[object, Set[str]] = defaultdict(set)

        self.entry_contexts_by_block = defaultdict(set)
        self.root_function_by_owner = {}

    # Construct reverse ICFG once
    def rebuild_predecessors(self):
        self.predecessors.clear()
        self.call_predecessors.clear()

        # Intraprocedural CFG predecessors
        for source_bid, info in self.blocks.items():
            for destination_bid in info.get("succ", set()):
                if destination_bid in self.blocks: self.predecessors[destination_bid].add(source_bid)

        # Interprocedural call predecessors
        for source_bid, destinations in self.call_edges.items():
            if source_bid not in self.blocks: continue
            for destination_bid in destinations:
                if destination_bid in self.blocks: self.call_predecessors[destination_bid].add(source_bid)

    def cfg_successors(self, bid: BasicBlock): return set(self.blocks.get(bid, {}).get("succ", set()))
    def call_successors(self, bid: BasicBlock): return set(self.call_edges.get(bid, set()))

    # May-reachability relation: (i) ordinary CFG continuation remains reachable after call; (b) resolved callee body also reachable during call
    def reachability_successors(self, bid: BasicBlock): return self.cfg_successors(bid) | self.call_successors(bid)

    # Compute interprocedural read influence to a monotone fixed point
    def compute_sensitive_read_events(
        self,
        keep,
    ):
        functions_by_key = {
            function_key(fn): fn
            for fn in self.fn_lookup.values()
        }

        functions = [
            functions_by_key[key]
            for key in sorted(
                functions_by_key
            )
        ]

        summaries = (
            _compute_function_influence_summaries(
                functions,
                keep=keep,
            )
        )

        self.function_influence_summaries = (
            summaries
        )

        self.sensitive_read_events.clear()
        self.sensitive_locations_by_block.clear()
        self.sink_reads_by_site.clear()

        for summary in summaries.values():
            self.sensitive_read_events.update(
                summary.read_to_sink
            )
            for sink_site, events in summary.sink_reads.items():
                self.sink_reads_by_site[sink_site].update(events)

        for event in self.sensitive_read_events:
            self.sensitive_locations_by_block[
                event.block_id
            ].add(event.location)

    def compute_function_write_summaries(self, keep):
        functions = sorted(
            set(self.fn_lookup.values()),
            key=function_key,
        )
        summaries = {
            fn: FunctionWriteSummary()
            for fn in functions
        }

        # Phase 1: monotone may-write summaries.
        changed = True
        while changed:
            changed = False
            for fn in functions:
                may_writes = set()
                for node in getattr(fn, "nodes", []) or []:
                    bid = (function_key(fn), node.node_id)
                    if bid not in keep or bid not in self.blocks:
                        continue
                    may_writes.update(self.blocks[bid]["writes"])
                    for ir in _ssa_irs(node):
                        if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)):
                            continue
                        callee_summary = summaries.get(getattr(ir, "function", None))
                        if callee_summary is None:
                            continue
                        substitutions = _call_key_substitutions(ir, fn)
                        may_writes.update(
                            _instantiate_location_template(location, substitutions)
                            for location in callee_summary.may_writes
                        )
                if not may_writes.issubset(summaries[fn].may_writes):
                    summaries[fn].may_writes.update(may_writes)
                    changed = True

        # Phase 2: greatest fixed point for must writes.
        for fn in functions:
            summaries[fn].must_writes = set(summaries[fn].may_writes)

        changed = True
        while changed:
            changed = False
            for fn in functions:
                nodes = [
                    node for node in (getattr(fn, "nodes", []) or [])
                    if (function_key(fn), node.node_id) in keep
                    and (function_key(fn), node.node_id) in self.blocks
                ]
                if not nodes:
                    candidate = set()
                else:
                    bids = {(function_key(fn), node.node_id) for node in nodes}
                    universe = set(summaries[fn].may_writes)
                    out_sets = {bid: set(universe) for bid in bids}
                    entry_bid = (
                        (function_key(fn), fn.entry_point.node_id)
                        if getattr(fn, "entry_point", None) is not None
                        else None
                    )
                    local_changed = True
                    while local_changed:
                        local_changed = False
                        for node in sorted(nodes, key=lambda item: item.node_id):
                            bid = (function_key(fn), node.node_id)
                            predecessors = self.predecessors.get(bid, set()) & bids
                            if bid == entry_bid or not predecessors:
                                incoming = set()
                            else:
                                incoming = set.intersection(
                                    *(out_sets[pred] for pred in predecessors)
                                )
                            generated = set(self.blocks[bid]["writes"])
                            for ir in _ssa_irs(node):
                                if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)):
                                    continue
                                callee_summary = summaries.get(getattr(ir, "function", None))
                                if callee_summary is None:
                                    continue
                                substitutions = _call_key_substitutions(ir, fn)
                                generated.update(
                                    _instantiate_location_template(location, substitutions)
                                    for location in callee_summary.must_writes
                                )
                            new_out = incoming | generated
                            if new_out != out_sets[bid]:
                                out_sets[bid] = new_out
                                local_changed = True

                    exits = [
                        (function_key(fn), node.node_id)
                        for node in nodes
                        if not any(
                            (function_key(fn), son.node_id) in bids
                            for son in (getattr(node, "sons", []) or [])
                        )
                        and str(getattr(node, "type", "")).lower() not in {"throw", "revert"}
                    ]
                    candidate = (
                        set.intersection(*(out_sets[bid] for bid in exits))
                        if exits else set()
                    )
                if candidate != summaries[fn].must_writes:
                    summaries[fn].must_writes = candidate
                    changed = True

        self.function_write_summaries = summaries

    # Return relation-member locations at this block that reach a sensitive operation
    def sensitive_relation_reads(self, bid, relation):
        relation_locations = (
            self.relation_reads
            .get(relation, {})
            .get(bid, set())
        )

        sensitive_locations = (
            self.sensitive_locations_by_block
            .get(bid, set())
        )

        if (not relation_locations or not sensitive_locations):
            return set()

        matched = set()
        for relation_location in (relation_locations):
            for sensitive_location in (sensitive_locations):
                if self._location_matches_member(sensitive_location, relation_location):
                    matched.add(relation_location)
                    break

        return matched

    # Return whether the exact read block and state location reaches a sensitive operation
    def read_event_is_sensitive(self, bid, var) -> bool:
        locations = (
            self.sensitive_locations_by_block
            .get(bid, set())
        )

        if not locations: return False
        if getattr(var, "vars", None) is not None:
            return bool(self.sensitive_relation_reads(bid, var))

        return any(self._location_matches_member(location, var) for location in locations)

    @staticmethod
    def _location_matches_member(observed, expected) -> bool:
        return location_matches_member(observed, expected)

    # Compute multi-return summaries before block processing
    def precompute_return_summaries(self,functions):
        self.fn_returns.clear()
        self.fn_return_components.clear()
        if not ENABLE_MULTI_RETURN_GROUPS: return

        summaries = ( _compute_function_influence_summaries(functions,keep=None) )
        for fn in functions:
            # Preserve the existing restriction: relation-return helpers must not mutate persistent state
            writes_storage = False
            for node in fn.nodes:
                if any(isinstance(variable, StateVariable) for variable in node.variables_written):
                    writes_storage = True
                    break

                if any(_is_storage_lvalue(ir) for ir in _ssa_irs(node)):
                    writes_storage = True
                    break

            if writes_storage: continue

            component_locations = {}
            summary = summaries[fn]

            for (return_index, locations) in summary.return_locations.items():
                if locations: component_locations[return_index] = set(locations)

            all_locations = set()
            for locations in (component_locations.values()):
                all_locations.update(locations)

            if len(all_locations) < 2: continue
            self.fn_return_components[fn] = component_locations
            self.fn_returns[fn] = all_locations

    # Populate the ICFG with one basic block & its inter-procedural edges
    def add_block(self, node: Node):
        block_id: BasicBlock = (function_key(node.function), node.node_id)
        fn = node.function

        # Processed these already
        if block_id in self.blocks: return
        self.node_lookup[block_id] = node

        # Gather storage reads and writes
        legacy_reads = {
            variable
            for variable in (
                getattr(node, "variables_read", []) or []
            )
            if isinstance(variable, StateVariable)
        }

        legacy_writes = {
            variable
            for variable in (
                getattr(node, "variables_written", []) or []
            )
            if isinstance(variable, StateVariable)
        }

        fn_key = function_key(fn)
        reference_locations = (self.reference_locations_by_function.get(fn_key))

        if reference_locations is None:
            reference_locations = (_function_reference_locations(fn,keep=None))
            self.reference_locations_by_function[fn_key] = reference_locations

        (
            ir_reads,
            ir_writes,
            precise_read_bases,
            precise_write_bases,
            unresolved_read_bases,
            unresolved_write_bases,
        ) = _node_storage_accesses(node, reference_locations)

        reads: Set[StateVariable | MappingSlotVar | ExternalStateVar] = set(legacy_reads)
        writes: Set[StateVariable | MappingSlotVar | ExternalStateVar] = set(legacy_writes)

        if MAPPING_MODE == "precise":
            # Remove a coarse node-level base mapping only when every observed access
            # to that base in this block was reconstructed precisely.
            for base in precise_read_bases:
                if base not in unresolved_read_bases: reads.discard(base)

            for base in precise_write_bases:
                if base not in unresolved_write_bases: writes.discard(base)

        # Add exact slots, scalar state accesses, and any unresolved base mapping fallback
        reads.update(ir_reads)
        writes.update(ir_writes)

        # Map local storage writes to external-state abstractions
        for written_location in list(writes):
            base_variable = (
                written_location.base
                if isinstance(
                    written_location,
                    MappingSlotVar,
                )
                else written_location
            )

            if not isinstance(base_variable, StateVariable): continue
            selector = STORAGE_TO_SELECTOR.get(base_variable.name)
            if not selector: continue
            token_address = contract_id(node.function.contract_declarer)

            alias_variable = ALIAS_REG.get_or_create(
                token_address,
                selector,
                (written_location.key,) if isinstance(written_location, MappingSlotVar) else (),
                lambda: ExternalStateVar(
                    selector,
                    token_address,
                    (written_location.key,) if isinstance(written_location, MappingSlotVar) else (),
                ),
            )

            writes.add(alias_variable)

        # HELPFUL DEBUGS FROM EARLIER
        # diagnostic debug for fn_returns [this finding actually helped us reach our milestone of MV-SI detection!]
        # if fn.name == "stakedAndActionLockedBalanceOf":
        #     print("[diag ]", fn.full_name, "view?", _is_view_only(fn), "internal_calls:", len(getattr(fn, "internal_calls", [])))
        #print(f"[summary] {fn.full_name} -> {', '.join(v.name for v in expr_vars)}") # [DEBUG] shows us summaries of |fn| >= 2

        # Tags conditionals that mix >=2 variables
        if ENABLE_BRANCH_GROUPS and node.type in branch_types:
            cond_vars  = set()

            # Plain state variables already seen as reads
            cond_vars.update(
                variable
                for variable in (getattr(node, "variables_read", []) or [])
                if (isinstance(variable, StateVariable) and relation_member_is_eligible(variable))
            )

            # Mapping/array slots already seen as reads
            for variable in (getattr(node, "variables_read", []) or []):
                if not is_index_var(variable): continue
                slot = mk_slot(variable.variable_left, variable.variable_right, fn)
                if relation_member_is_eligible(slot): cond_vars.add(slot)

            # External GSV wrappers already seen as reads
            cond_vars.update(location for location in reads if relation_member_is_eligible(location))

            # Inline summaries of view and pure calls
            for ir in node.irs:
                if (
                    isinstance(
                        ir,
                        (HighLevelCall, InternalCall),
                    )
                    and ir.function in self.fn_returns
                ):
                    instantiated_returns = (
                        _subst_returns_with_args(
                            ir.function,
                            ir,
                            self.fn_returns[
                                ir.function
                            ],
                            fn,
                        )
                    )

                    cond_vars.update(
                        instantiated_returns
                    )

                    reads.update(
                        instantiated_returns
                    )

                elif (
                    isinstance(
                        ir,
                        (HighLevelCall, InternalCall),
                    )
                    and ir.function is None
                ):
                    callee_fn = resolve_unresolved_callee(
                        ir,
                        node.function,
                        self.fn_lookup,
                    )

                    if (
                        callee_fn
                        and callee_fn in self.fn_returns
                    ):
                        instantiated_returns = (
                            _subst_returns_with_args(
                                callee_fn,
                                ir,
                                self.fn_returns[
                                    callee_fn
                                ],
                                fn,
                            )
                        )

                        cond_vars.update(
                            instantiated_returns
                        )

                        reads.update(
                            instantiated_returns
                        )

            cond_vars = { location for location in cond_vars if relation_member_is_eligible(location) }

            # Show the raw variables seen in this conditional
            if cond_vars:
                fmt = ", ".join(v.name for v in cond_vars)

                # [DEBUG] shows conditional variables
                #print(f"[cond  ] {fn.full_name}:{node.source_mapping.lines[0]} -> {fmt}")

            # We care iff 2 or more variables involved
            if len(cond_vars) >= 2:
                # We use a cheap unique gid to classify
                gid = f"branch::{function_key(fn)}::{node.node_id}"
                for cv in cond_vars:
                    self.branch_groups[gid].add(cv)
                    self.var_to_branchgroups[cv].add(gid)

                    # Additionally tag the mapping base so all keys share the group
                    # print(f"[PROMOTE_MAPPING_BASE] Set to {PROMOTE_MAPPING_BASE}.")
                    if isinstance(cv, MappingSlotVar) and PROMOTE_MAPPING_BASE:
                        base = cv.base
                        if relation_member_is_eligible(base):
                            self.branch_groups[gid].add(base)
                            self.var_to_branchgroups[base].add(gid)

                # [DEBUG] shows groups for branching
                #print(f"[group] {gid} <- {', '.join(v.name for v in self.branch_groups[gid])}")

        # ERC-20 balance mapping writes should alias EXT::balanceof
        if ENABLE_EXTERNAL_STATE:
            for ir in node.irs:
                if not isinstance(ir, OperationWithLValue): continue
                if getattr(ir.lvalue, "name", "") in ("balances", "_balances", "balanceOf"):
                    token_addr = contract_id(node.function.contract_declarer)
                    written_location = next(
                        (location for location in writes if isinstance(location, MappingSlotVar)
                         and location.base.name in ("balances", "_balances", "balanceOf")),
                        None,
                    )
                    external_args = (written_location.key,) if written_location is not None else ()
                    writes.add(ExternalStateVar("balanceof", token_addr, external_args))

        # Does contract expose a public getter?
        if ENABLE_EXTERNAL_STATE and any(isinstance(v, StateVariable) and v.name == "_lastBalance" for v in writes):
            if any(f.name == "lastBalance" and f.visibility == "public" for f in node.function.contract_declarer.functions_declared):
                token_addr = contract_id(node.function.contract_declarer)
                writes.add(ExternalStateVar("lastbalance", token_addr))

        # Intra-procedural successors
        succ: Set[BasicBlock] = { (function_key(s.function), s.node_id) for s in node.sons }

        # Handle every call IR in this block
        for ir in node.irs:

            # Drop any IR that isn't a high-level or internal call
            if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)): continue

            # Call-graph edges could be Function, None, or Variable
            callee = ir.function
            if getattr(callee, "entry_point", None) is not None:
                entry_bid = (function_key(callee), callee.entry_point.node_id)

                # Call edge separated from ordinary CFG continuation
                self.call_edges[block_id].add(entry_bid)
                if isinstance(ir, (InternalCall, LibraryCall)):
                    edge_mode = ("preserve", None)
                else:
                    target_contract = (
                        getattr(callee, "contract", None)
                        or getattr(callee, "contract_declarer", None)
                    )
                    edge_mode = ("switch", contract_storage_key(target_contract))
                edge_key = (block_id, entry_bid)
                previous_mode = self.call_edge_context_modes.get(edge_key)
                if previous_mode is not None and previous_mode != edge_mode:
                    raise RuntimeError(
                        "MV-Scan found conflicting storage-context semantics "
                        f"for call edge {edge_key}: {previous_mode} vs {edge_mode}"
                    )
                self.call_edge_context_modes[edge_key] = edge_mode

            # Summarize view/pure returns into reads at the call site
            if callee in self.fn_returns:
                reads |= _subst_returns_with_args(callee, ir, self.fn_returns[callee], fn)
            elif callee is None:
                callee_fn = resolve_unresolved_callee(ir, node.function, self.fn_lookup)
                if callee_fn and callee_fn in self.fn_returns:
                    reads |= _subst_returns_with_args(callee_fn, ir, self.fn_returns[callee_fn], fn)

            # External-state abstraction
            callee_sel = str(ir.function_name).split('(')[0].lower()
            if ENABLE_EXTERNAL_STATE and (callee_sel in EXT_READS or callee_sel in EXT_WRITES):
                # Best-effort stable address string
                dest = getattr(ir, "destination", None)
                addr = getattr(dest, "canonical_name", getattr(dest, "name", None))
                canonical_args = tuple(
                    canon_key(argument, node.function)
                    for argument in (getattr(ir, "arguments", []) or [])
                )

                # Obtain 1 canonical wrapper for this call-site
                def mk_wrapper():
                    return ExternalStateVar(callee_sel, addr, canonical_args)

                ext_var = ALIAS_REG.get_or_create(addr, callee_sel, canonical_args, mk_wrapper)
                if callee_sel in EXT_READS: reads.add(ext_var)
                if callee_sel in EXT_WRITES: writes.add(ext_var)

        # Commits the caller block and updates
        self.blocks[block_id] = { "reads": reads, "writes": writes, "succ": succ }
        self.fn_lookup[function_key(node.function)] = node.function
        for v in reads: self.var_reads[v].add(block_id)
        for v in writes: self.var_writes[v].add(block_id)

### ICFG helpers

branch_types = {NodeType.IF}
for t in ("REQUIRE", "ASSERT", "REVERT"):
    if hasattr(NodeType, t): branch_types.add(getattr(NodeType, t))

# Node lookup
def node_by_id(fn, node_id):
    for n in fn.nodes:
        if n.node_id == node_id: return n
    return None

def var_used(node, v):
    return v in getattr(node, "state_variables_read", []) or v in getattr(node, "variables_read", [])

# A call that invokes require or assert
def is_require_like(node):
    try: return "require(" in str(node.expression) or "assert(" in str(node.expression)
    except Exception: return False

def _is_relation_entity(var) -> bool:
    return ( getattr(var, "vars", None) is not None )

def _matching_relation_members(relation, location):
    return matching_relation_members(relation.vars, location)


def _match_kind(location, member) -> str:
    return "exact" if location == member else "mapping_base_wildcard"


def _relation_access_evidence(icfg, relation, writer_bid, reader_bid):
    writer_locations = (
        icfg.relation_writes
        .get(relation, {})
        .get(writer_bid, set())
    )

    reader_locations = icfg.sensitive_relation_reads(reader_bid, relation)

    if not writer_locations or not reader_locations:
        return ()
    best_by_member_edge = {}
    for writer_location in sorted(writer_locations, key=state_entity_sort_key):
        writer_members = _matching_relation_members(relation, writer_location)
        for reader_location in sorted(reader_locations, key=state_entity_sort_key):
            reader_members = _matching_relation_members(relation, reader_location)
            for writer_member in writer_members:
                for reader_member in reader_members:
                    if writer_member == reader_member:
                        continue
                    evidence = RelationAccessEvidence(
                        writer_location=writer_location,
                        writer_member=writer_member,
                        reader_location=reader_location,
                        reader_member=reader_member,
                        writer_match_kind=_match_kind(writer_location, writer_member),
                        reader_match_kind=_match_kind(reader_location, reader_member),
                    )
                    edge_key = (writer_member, reader_member)
                    rank = (
                        evidence.writer_match_kind != "exact",
                        evidence.reader_match_kind != "exact",
                        state_entity_sort_key(evidence.writer_location),
                        state_entity_sort_key(evidence.reader_location),
                    )
                    existing = best_by_member_edge.get(edge_key)
                    if existing is None or rank < existing[0]:
                        best_by_member_edge[edge_key] = (rank, evidence)
    return tuple(
        evidence for _, evidence in sorted(
            best_by_member_edge.values(), key=lambda item: item[0]
        )
    )

def _block_writes_entity(icfg, bid, var) -> bool:
    writes = (
        icfg.blocks
        .get(bid, {})
        .get("writes", set())
    )

    if var in writes: return True

    members = getattr(var, "vars", None)
    if members is None: return False
    return any(
        location_matches_member(written_location, member)
        for written_location in writes
        for member in members
    )

# Return whether dst is reachable from src within the same function without an intervening overwrite of var.
def same_function_reachable_without_overwrite(icfg: ICFG, src_bid: BasicBlock, dst_bid: BasicBlock, var) -> bool:
    if src_bid == dst_bid: return True
    if src_bid[0] != dst_bid[0]: return False

    seen = {src_bid}
    queue = deque([src_bid])
    while queue:
        current = queue.popleft()
        successors = sorted(icfg.blocks.get(current, {}).get("succ", set()), key=basic_block_sort_key)
        for successor in successors:
            # Operation ordering must use only intraprocedural CFG edges
            if successor[0] != src_bid[0]: continue
            if successor == dst_bid: return True
            if successor in seen: continue

            if _block_writes_entity(icfg, successor, var): continue
            seen.add(successor); queue.append(successor)

    return False

# Classify using CFG reachability, never block-ID tuple ordering
def classify_witness_operation(icfg: ICFG, writer_bid: BasicBlock, reader_bid: BasicBlock, var):
    if writer_bid[0] != reader_bid[0]: return "cross_tx_stale_read", False, False

    writer_reaches_reader = (same_function_reachable_without_overwrite(icfg, writer_bid, reader_bid, var))
    reader_reaches_writer = (same_function_reachable_without_overwrite(icfg, reader_bid, writer_bid, var))
    if writer_reaches_reader and not reader_reaches_writer:
        return "stale_read", True, False
    if reader_reaches_writer and not writer_reaches_reader:
        return "destructive_write", False, True
    if writer_reaches_reader and reader_reaches_writer:
        return "cyclic_state_inconsistency", True, True
    return "unordered_state_inconsistency", False, False

# Returns iff dst_bid is reachable from src_bid without passing through a block that writes `v` (other than the src)
def reachable_without_overwrite(icfg: ICFG, src_bid, dst_bid, v) -> bool:
    # If the read happens in a block that is itself a branch/ext-call sink
    if src_bid == dst_bid: return True

    seen, q = set([src_bid]), deque([src_bid])
    while q:
        cur = q.popleft()
        for nxt in icfg.reachability_successors(cur):
            # Reached target
            if nxt == dst_bid: return True

            # Already visited
            if nxt in seen: continue

            # Overwrote v, continue
            if _block_writes_entity(icfg,nxt,v): continue

            seen.add(nxt)
            q.append(nxt)
    return False

# Yields exact RawStateWitness instances
def stale_read_pairs(icfg: ICFG, reader_filter=None, pair_stats=None):
    pair_stats = pair_stats if pair_stats is not None else defaultdict(int)
    variables = sorted(icfg.var_writes.keys(), key=state_entity_sort_key)
    for var in variables:
        if var is None: continue
        pair_stats["variables_considered"] += 1
        
        # Canonical MV mode analyzes semantic relations; omits SV
        is_relation = _is_relation_entity(var)
        if not is_relation and not INCLUDE_SCALAR_WITNESSES:
            pair_stats["scalar_variables_skipped"] += 1
            continue
        if isinstance(var, StateVariable):
            if is_const(var) or is_role_bytes32(var): continue

        writes = {
            writer_bid
            for writer_bid in icfg.var_writes.get(var, set())
            if not (
                icfg.fn_lookup[writer_bid[0]].is_constructor
                or icfg.fn_lookup[writer_bid[0]].name.startswith("initialize")
            )
        }

        if not writes: continue

        reads = {
            reader_bid
            for reader_bid in icfg.var_reads.get(var, set())
            if not (
                icfg.fn_lookup[reader_bid[0]].is_constructor
                or icfg.fn_lookup[reader_bid[0]].name.startswith("initialize")
            )
        }

        if not reads: continue
        sorted_writes = sorted(writes, key=basic_block_sort_key)
        sorted_reads = sorted(reads, key=basic_block_sort_key)

        # Determine reader eligibility once before combining each reader with every writer
        eligible_readers = []
        for reader_bid in sorted_reads:
            if not icfg.read_event_is_sensitive(reader_bid, var):
                pair_stats["insensitive_readers_filtered"] += 1
                continue
            if (reader_filter is not None and not reader_filter(var, reader_bid)):
                pair_stats["sink_filtered"] += 1
                continue
            eligible_readers.append(reader_bid)

        if not eligible_readers: continue
        pair_stats["eligible_readers"] += len(eligible_readers)

        # Determine writer eligibility once
        eligible_writers = []
        for writer_bid in sorted_writes:
            if (NOOP_WRITE_FILTER and not is_relation):
                writer_fn = icfg.fn_lookup[writer_bid[0]]
                writer_node = node_by_id(writer_fn, writer_bid[1])

                if (writer_node is not None and is_self_copy_write(var, writer_node)):
                    pair_stats["noop_write_filtered"] += 1
                    continue

            eligible_writers.append(writer_bid)
        
        if not eligible_writers: continue
        pair_stats["eligible_writers"] += len(eligible_writers)

        writer_slot_keys, reader_slot_keys = {}, {}
        if (REQUIRE_SAME_SLOT_KEY and not is_relation):
            writer_slot_keys = {
                writer_bid: slot_keys_at(icfg, writer_bid, "writes")
                for writer_bid in eligible_writers
            }

            reader_slot_keys = {
                reader_bid: slot_keys_at(icfg, reader_bid, "reads") for reader_bid in eligible_readers
            }

        exact_seen = set()
        for writer_bid in eligible_writers:
            for reader_bid in eligible_readers:
                pair_stats["raw_block_pairs"] += 1
                # Skip only the literal same static block
                if writer_bid == reader_bid:
                    pair_stats["same_static_block_filtered"] += 1
                    continue

                relation_evidence = ()
                if is_relation:
                    relation_evidence = _relation_access_evidence(
                        icfg, var, writer_bid, reader_bid
                    )
                    if not relation_evidence:
                        pair_stats["relation_incompatible"] += 1
                        continue
                    pair_stats["relation_evidence_edges"] += len(relation_evidence)

                exact_key = (writer_bid, reader_bid, var)
                if exact_key in exact_seen:
                    pair_stats["exact_duplicate_filtered"] += 1
                    continue

                if (REQUIRE_SAME_SLOT_KEY and not is_relation):
                    writer_keys = writer_slot_keys[writer_bid]
                    reader_keys = reader_slot_keys[reader_bid]
                    common_bases = (set(writer_keys) & set(reader_keys))

                    if (common_bases and not any(writer_keys[base] & reader_keys[base] for base in common_bases)):
                        pair_stats["same_slot_key_filtered"] += 1
                        continue

                (operation_pattern, writer_reaches_reader, reader_reaches_writer) = classify_witness_operation(icfg, writer_bid, reader_bid, var)
                exact_seen.add(exact_key)

                yield RawStateWitness(
                    writer_bid=writer_bid,
                    reader_bid=reader_bid,
                    variable=var,
                    operation_pattern=operation_pattern,
                    writer_reaches_reader=(writer_reaches_reader),
                    reader_reaches_writer=(reader_reaches_writer),
                    relation_evidence=relation_evidence,
                )
