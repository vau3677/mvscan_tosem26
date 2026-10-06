"""
State-annotated interprocedural control-flow graph (ICFG).

Each physical Slither CFG block is stored once under a source-qualified
function identity. Intraprocedural continuation and call-entry edges remain
separate. Relations are bounded co-influence hypotheses, not proven
invariants, feasible paths, or exploits.
"""
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Hashable, Set, Tuple
from slither.core.cfg.node import Node, NodeType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Assignment, Call, Condition, EventCall, HighLevelCall, Index, InternalCall, LibraryCall, Member, OperationWithLValue, Phi, Return, SolidityCall, Unpack
from slither.slithir.variables import ReferenceVariable
from .mvscan_env import env_bool, env_enum

BasicBlock = Tuple[str, int]           # Indexed by its fn key and Slither node number
CallSiteId = tuple[BasicBlock, int]    # Disambiguates many call IRs emitted for same node
_ARG_PATTERN = re.compile(r"\$arg\d+")

# Access to Slither's object model
def attr(obj, name, default=None): return getattr(obj, name, default)

# Resolved call-entry transition with storage mode and key substitutions
# ``storage_mode`` separates calls using storage from those executing in storage
# ``substitutions`` instantiates callee mapping-key parameter templates
@dataclass(frozen=True, slots=True)
class CallEdgeRecord:
    source_bid: BasicBlock
    target_bid: BasicBlock
    callsite_id: CallSiteId
    target_function_key: str
    storage_mode: str
    target_storage_context: str | None
    substitutions: tuple[tuple[str, str], ...]

@dataclass(frozen=True, slots=True, order=True)
class ExecutionContext:
    """Immutable root, storage, binding, and active-sender call context."""
    owner: str
    storage_context: str
    bindings: tuple[tuple[str, str], ...] = ()
    active_sender: str = ""

    # Expose immutable bindings as a lookup map
    @property
    def binding_map(self) -> dict[str, str]: return dict(self.bindings)

# Yield stable per-block call-site identifiers alongside their call IRs.
def iter_call_sites(node):
    call_ordinal = 0
    for ir in _ssa_irs(node):
        if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)): continue
        callsite_id = ((function_key(node.function), node.node_id), call_ordinal)
        yield callsite_id, ir
        call_ordinal += 1

# Exact logical state location read at one basic block
@dataclass(frozen=True, slots=True)
class ReadEvent:
    block_id: BasicBlock
    location: Hashable

# Formal-parameter source used while propagating value influence
@dataclass(frozen=True, slots=True)
class ParameterOrigin:
    index: int

# Values tracked by influence analysis originate in state or a formal arg
Origin = ReadEvent | ParameterOrigin

# Sensitive op reached by an influenced value at one IR index
@dataclass(frozen=True, slots=True)
class SinkSite:
    block_id: BasicBlock
    ir_index: int
    kind: str

# Returned component at a particular return instruction
@dataclass(frozen=True, slots=True)
class ReturnSite:
    block_id: BasicBlock
    ir_index: int
    return_index: int

@dataclass(slots=True)
class FunctionInfluenceSummary:
    """Monotone interprocedural may-summary for sinks and return components."""
    # Formal params whose values can reach sensitive operations
    parameter_to_sink: set[int] = field(default_factory=set)

    # return index -> formal parameters affecting that return component
    parameter_to_returns: DefaultDict[int, set[int]] = field(default_factory=lambda: defaultdict(set))

    # Exact state-read events reaching sensitive operations.
    read_to_sink: set[ReadEvent] = field(default_factory=set)

    # return index -> exact state-read events affecting that component
    read_to_returns: DefaultDict[int, set[ReadEvent]] = field(default_factory=lambda: defaultdict(set))

    # Logical locations represented by each returned component, expressed in this fn's param namespace
    return_locations: DefaultDict[int, set[Hashable]] = field(default_factory=lambda: defaultdict(set))
    return_locations_by_site: DefaultDict[ReturnSite, set[Hashable]] = field(default_factory=lambda: defaultdict(set))

    sink_reads: DefaultDict[SinkSite, set[ReadEvent]] = field(default_factory=lambda: defaultdict(set))
    sink_parameters: DefaultDict[SinkSite, set[int]] = field(default_factory=lambda: defaultdict(set))

@dataclass(slots=True)
class FunctionWriteSummary:
    """Interprocedural may-write and conservative must-write summary."""
    may_writes: set[Hashable] = field(default_factory=set)
    must_writes: set[Hashable] = field(default_factory=set)

_VALID_ABLATIONS = { "full", "sv_only", "no_branch_groups", "no_multi_return_groups", "no_external_state", "mapping_insensitive" }
MVSCAN_ABLATION = env_enum("MVSCAN_ABLATION", "full", _VALID_ABLATIONS)

INCLUDE_SCALAR_WITNESSES = (MVSCAN_ABLATION == "sv_only" or env_bool("MVSCAN_INCLUDE_SCALAR_WITNESSES", False))
ENABLE_BRANCH_GROUPS = (MVSCAN_ABLATION not in {"sv_only", "no_branch_groups"})
ENABLE_MULTI_RETURN_GROUPS = (MVSCAN_ABLATION not in {"sv_only", "no_multi_return_groups"})
ENABLE_EXTERNAL_STATE = (MVSCAN_ABLATION != "no_external_state")
MAPPING_MODE = ("base_collapsed" if MVSCAN_ABLATION == "mapping_insensitive" else "precise")
NOOP_WRITE_FILTER = env_bool("NOOP_WRITE_FILTER", True) # Implements DivertScan's §4.2.3 P.4

# Require same mapping-slot key for r/w pairs when both sides use slots of the same base mapping
REQUIRE_SAME_SLOT_KEY = env_bool("REQUIRE_SAME_SLOT_KEY", True) and MAPPING_MODE == "precise"

# Mapping-key agreement utility: return {base_map_sv -> set(keys)} seen at block for r/w
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

# Normalize expression, preserving exact id details
def identity_txt(value) -> str:
    text = str(value or "").replace("this.", "")
    text = re.sub(r"\baddress\((.+?)\)", r"\1", text)
    return re.sub(r"\s+", "", text)

def _non_ssa_variable(var): return attr(var, "non_ssa_version", var) # Collapse SSA var to its concrete src var

# Yield each formal index with its SSA and non-SSA param variants
def _parameter_variants(fn):
    parameters_ssa = list(attr(fn, "parameters_ssa", []) or [])
    params = list(attr(fn, "parameters", []) or [])
    for index in range(max(len(parameters_ssa), len(params))):
        yield index, tuple(params_l[index] for params_l in (parameters_ssa, params) if index < len(params_l))

# Find which formal param, if any, an SSA operand represents
def _formal_parameter_index(fn, operand):
    if fn is None or operand is None: return None
    concrete_operand = _non_ssa_variable(operand)
    for index, candidates in _parameter_variants(fn):
        for parameter in candidates:
            if operand is parameter: return index
            concrete_parameter = (_non_ssa_variable(parameter))
            if concrete_operand is concrete_parameter: return index
            try:
                if concrete_operand == concrete_parameter: return index
            except Exception:
                pass
    return None

# Clear process-global analysis caches between compilation units
_PARAMETER_ALIAS_CACHE = {}
def reset_icfg_analysis_caches(): _PARAMETER_ALIAS_CACHE.clear()

_CANONICAL_KEY_PREFIXES = ( "$arg", "$sender", "@state::", "@const::", "@local::", "@unknown::", "@txarg::", "@sender::", "@contract::", "@unknown-receiver::" )

# Convert mapping key or argument into MV-Scan's term language
def canon_key(key, fn=None) -> str:
    if (isinstance(key, str) and key.startswith(_CANONICAL_KEY_PREFIXES)): return key

    parameter_index = _formal_parameter_index(fn, key)
    if parameter_index is not None: return f"$arg{parameter_index}"

    if fn is not None:
        aliases = _function_parameter_aliases(fn)
        indexes = set(aliases.get(key, set()))
        indexes.update(aliases.get(_non_ssa_variable(key), set()))
        if len(indexes) == 1: return f"$arg{next(iter(indexes))}"

    text = identity_txt(key)
    if text.lower() in {"msg.sender", "_msgsender()", "_msgsender"}: return "$sender"

    concrete = _non_ssa_variable(key)
    if isinstance(concrete, StateVariable):
        canonical_name = (getattr(concrete, "canonical_name", None) or getattr(concrete, "name", None) or str(concrete))
        return "@state::" + source_file_key(concrete) + "::" + str(canonical_name)
    if _looks_like_literal(key): return "@const::" + text
    if fn is not None: return ("@local::" + function_key(fn) + "::" + type(concrete).__name__ + "::" + text)
    return "@unknown::" + type(concrete).__name__ + "::" + text

# Extract normalized variable text for no-op write comparison
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
    if type(v).__name__ == "ExternalStateVar": return False  # Don't attempt on externals

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

# Canonical, hashable sequence of keys for a nested mapping access
@dataclass(frozen=True, slots=True)
class MappingKeyPath:
    components: tuple[str, ...]

    # Render nested mapping components in Solidity indexing form
    def __str__(self) -> str: return "][".join(self.components)

class MappingSlotVar:
    """Hashable mapping/array location with a complete canonical key path."""
    __slots__ = ("base", "key_path")

    # Normalize a mapping access into a base var and structured key path
    def __init__(self, base: StateVariable, key: str | MappingKeyPath):
        self.base = base # StateVariable
        self.key_path = (key if isinstance(key, MappingKeyPath) else MappingKeyPath(split_key_path(str(key))))

    # Render path of a nested mapping slot
    @property
    def key(self) -> str: return str(self.key_path)

    # Hash mapping accesses by their base var and complete key path
    def __hash__(self): return hash((self.base, self.key_path))

    # Compare mapping accesses by base var and complete key path
    def __eq__(self, other):
        return (isinstance(other, MappingSlotVar) and self.base == other.base and self.key_path == other.key_path)

    # Render the mapping base and canonical key path for reports
    @property
    def name(self): return f"{self.base.name}[{self.key}]"

    def __str__(self):
        return self.name # @property
    __repr__ = __str__

# Match a concrete access location against one relation member
def location_matches_member(observed, expected) -> bool:
    if observed == expected: return True
    # Imprecise base mapping
    return bool(isinstance(expected, StateVariable) and isinstance(observed, MappingSlotVar) and observed.base == expected)

# Return exact relation members, falling back to compatible mapping bases
def matching_relation_members(members, observed) -> set:
    exact_matches = {member for member in members if observed == member}
    if exact_matches: return exact_matches
    return {
        member for member in members
        if (isinstance(member, StateVariable) and isinstance(observed, MappingSlotVar) and observed.base == member)
    }

def is_const(v: StateVariable) -> bool: return attr(v, "is_constant", False) or attr(v, "is_immutable", False)

# Detect if function can't write to storage
def is_view_only(fn) -> bool:
    if hasattr(fn, "state_mutability"): return fn.state_mutability in ("view", "pure")
    return attr(fn, "is_view", False) or attr(fn, "is_pure", False)

# Makes new mapping slot
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
    arguments = list(attr(ir, "arguments", []) or [])
    return { f"$arg{index}": canon_key(argument, caller_fn) for index, argument in enumerate(arguments)}

# Instantiate one abstract state location across a function call
def _instantiate_location_template(location, substitutions):
    if not isinstance(location, MappingSlotVar): return location
    return MappingSlotVar(location.base, _substitute_key_template(location.key, substitutions))

# Instantiate a flattened callee return summary at one concrete call site
def _subst_returns_with_args(callee, ir, expr_vars, caller_fn):
    return { _instantiate_location_template(returned_location, _call_key_substitutions(ir, caller_fn)) for returned_location in expr_vars }

class ExternalStateVar:
    """Receiver/selector/argument identity for state read by a static call."""
    __slots__ = ("selector", "addr", "args")

    # Normalize an external read into immutable receiver, selector, and args
    def __init__(self, selector: str, addr: str | None, args=()):
        self.selector = str(selector)
        self.addr = str(addr or "unknown")
        self.args = tuple(str(arg) for arg in args)

    # Render the receiver, selector, and arguments for diagnostics
    @property
    def name(self) -> str:
        rendered_args = ", ".join(self.args)
        return f"{self.addr}.{self.selector}({rendered_args})"

    # Hash external locations by their full call identity.
    def __hash__(self): return hash((self.selector, self.addr, self.args))

    # Compare external locations by their full call identity.
    def __eq__(self, other):
        return (isinstance(other, ExternalStateVar) and self.selector == other.selector and self.addr == other.addr and self.args == other.args)

    # Render the canonical external-state id used diagnostically
    def __str__(self): return f"EXT::{self.addr}::{self.selector}::{self.args}"
    __repr__ = __str__

# A relation member must represent mutable protocol state
def relation_member_is_eligible(entity) -> bool:
    base = entity.base if isinstance(entity, MappingSlotVar) else entity
    if isinstance(base, StateVariable): return not is_const(base)
    return isinstance(base, ExternalStateVar) # External state is a valid relation member

@dataclass(frozen=True, slots=True)
class RawStateWitness:
    """Exact block pair showing a write/read interference opportunity."""
    writer_bid: BasicBlock
    reader_bid: BasicBlock
    variable: object
    writer_reaches_reader: bool
    reader_reaches_writer: bool
    relation_evidence: tuple["RelationAccessEvidence", ...] = ()

@dataclass(frozen=True, slots=True)
class RelationAccessEvidence:
    """Concrete accesses matching distinct members of an inferred relation."""
    writer_location: Hashable
    writer_member: Hashable
    reader_location: Hashable
    reader_member: Hashable
    key_constraints: tuple["KeyEqualityConstraint", ...] = ()

@dataclass(frozen=True, slots=True)
class KeyEqualityConstraint:
    """Witness-local equality required for two symbolic accesses to alias."""
    left: str
    right: str

def basic_block_sort_key(bid): return str(bid[0]), int(bid[1]) # Sort bids by fn id & node number

# Produce a stable cross-type ordering key for state entities
def state_entity_sort_key(var) -> tuple:
    if isinstance(var, MappingSlotVar):
        base = var.base
        base_name = (getattr(base, "canonical_name", None) or getattr(base, "name", None) or str(base))
        return ("mapping_slot", source_file_key(base), str(base_name), str(var.key))

    if isinstance(var, ExternalStateVar): return ("external", str(var.addr), str(var.selector), var.args)
    canonical_name = (getattr(var, "canonical_name", None) or getattr(var, "name", None) or str(var))
    return (type(var).__name__, source_file_key(var), str(canonical_name))

def source_file_key(obj) -> str:
    source_mapping = attr(obj, "source_mapping")
    filename = attr(source_mapping, "filename")
    return str(attr(filename, "relative") or attr(filename, "short") or attr(filename, "absolute") or "<unknown-source>")

# Identify the contract whose storage is active for a call context
def contract_storage_key(contract) -> str:
    if contract is None: return "<unknown-storage-context>"
    cname = (getattr(contract, "canonical_name", None) or getattr(contract, "name", None) or "<unknown-contract>")
    source_path = source_file_key(contract).replace("\\", "/")
    return f"{source_path}::{cname}"

# Build collision-resistant, src-qualified function id
def function_key(fn) -> str:
    canonical_name = getattr(fn, "canonical_name", None)
    if not canonical_name:
        contract = getattr(fn, "contract_declarer", None)
        contract_name = (getattr(contract, "canonical_name", None) or getattr(contract, "name", None) or "<unknown-contract>")
        full_name = (getattr(fn, "full_name", None) or getattr(fn, "name", "<unknown-function>"))
        canonical_name = f"{contract_name}.{full_name}"
    return f"{source_file_key(fn)}::{canonical_name}"

# Normalize function or call declaration to its dispatch signature
def function_signature_key(fn) -> str:
    full_name = getattr(fn, "full_name", None)
    if full_name: return str(full_name)
    parameter_types = ",".join(str(parameter.type).replace(" ", "") for parameter in (getattr(fn, "parameters", []) or []))
    return f"{getattr(fn, 'name', '<unknown-function>')}({parameter_types})"

# Trick: evaluate if flag is value or method
def bool_attr(obj, name: str) -> bool:
    value = attr(obj, name, False)
    if callable(value):
        try: value = value()
        except TypeError: return False
    return bool(value)

# Check if declaration has executable nodes and an entrypoint
def function_has_body(fn) -> bool: return fn is not None and attr(fn, "entry_point") is not None

# Does declaration originate from dependency source code
def declaration_is_dependency(obj) -> bool: return bool(attr(attr(obj, "source_mapping"), "is_dependency", False))

# Resolve the apparent contract type of a high-level call receiver.
def receiver_contract_type(ir):
    destination = getattr(ir, "destination", None)
    candidates = [destination, getattr(destination, "type", None), getattr(getattr(destination, "type", None), "type", None), getattr(getattr(destination, "type", None), "contract", None)]
    for candidate in candidates:
        if candidate is not None and (hasattr(candidate, "functions") or hasattr(candidate, "functions_declared")):
            return candidate
    return None

# Collect a contract and all known inheritance ancestors
def contract_lineage(contract) -> set:
    if contract is None: return set()
    values = {contract}
    for attribute in ("inheritance", "linearized_base_contracts", "_linearizedBaseContracts"):
        values.update(getattr(contract, attribute, None) or [])
    return values

# Bind root params and sender placeholders to terms scoped to tx only
def root_context_bindings(fn, owner): return tuple((f"$arg{i}", f"@txarg::{owner}::{i}") for i, _ in enumerate(getattr(fn, "parameters", []) or []))

# Recognize Solidity literals that should be fixed during unification
def _looks_like_literal(value) -> bool:
    text = norm_txt(str(value))
    if text in {"true", "false"}: return True
    if re.fullmatch(r"\d+", text) or re.fullmatch(r"0x[0-9a-f]+", text): return True
    return type(_non_ssa_variable(value)).__name__.lower() in { "constant", "enum", "enumcontract", "enumtoplevel" }

# Substitute context bindings into a canonical mapping-key template
def instantiate_key_template(template: str, bindings, active_sender: str) -> str:
    current = str(template)
    if current == "$sender": return active_sender
    for _ in range(16):
        changed = False
        # Replace one arg placeholder and track fixed-point progress
        def replace(match):
            nonlocal changed
            placeholder = match.group(0)
            replacement = bindings.get(placeholder, placeholder)
            if replacement != placeholder: changed = True
            return replacement
        current = _ARG_PATTERN.sub(replace, current)
        if not changed: break
    else:
        return "@unknown::recursive-substitution::" + current
    return current.replace("$sender", active_sender)

# Check whether a key still contains context-dependent symbolic terms
def is_symbolic_key_template(key: str) -> bool:
    text = str(key)
    return (bool(_ARG_PATTERN.search(text)) or "$sender" in text or "msg.sender" in text or text.startswith(("@local::", "@unknown::")))

# Compose caller bindings with call arguments to form a callee context.
def compose_callee_bindings(caller_context: ExecutionContext, edge: CallEdgeRecord, relevant_formals):
    caller_bindings = caller_context.binding_map
    composed = {}
    for placeholder, caller_template in edge.substitutions:
        if placeholder not in relevant_formals: continue
        composed[placeholder] = instantiate_key_template(caller_template, caller_bindings, caller_context.active_sender or f"@sender::{caller_context.owner}")
    return tuple(sorted(composed.items()))

# Extract best available normalized signature from a call IR
def _call_signature_key(ir) -> str:
    apparent = getattr(ir, "function", None)
    if apparent is not None:
        signature = function_signature_key(apparent)
        if "(" in signature: return signature
    raw_name = str(getattr(ir, "function_name", "") or "")
    if "(" in raw_name: return raw_name
    argument_types = ",".join(str(getattr(argt, "type", "")).replace(" ", "") for argt in (getattr(ir, "arguments", []) or []))
    return f"{raw_name}({argument_types})"

# Canonicalize an external receiver, using call-site scope when unresolved
def external_receiver_term(ir, caller_fn, callsite_id) -> str:
    destination = getattr(ir, "destination", None)
    if destination is None:
        return ("@unknown-receiver::" + callsite_id[0][0] + "::" + str(callsite_id[0][1]) + "::" + str(callsite_id[1]))
    term = canon_key(destination, caller_fn)
    if term: return term
    return ("@unknown-receiver::" + callsite_id[0][0] + "::" + str(callsite_id[0][1]) + "::" + str(callsite_id[1]))

# Represent an unresolved external view result as an aliased state location
def external_view_location(ir, caller_fn, callsite_id):
    if not ENABLE_EXTERNAL_STATE or not isinstance(ir, HighLevelCall): return None
    apparent = getattr(ir, "function", None)
    if apparent is None or not is_view_only(apparent): return None
    if getattr(ir, "lvalue", None) is None: return None
    return ExternalStateVar(
        _call_signature_key(ir),
        external_receiver_term(ir, caller_fn, callsite_id),
        tuple(canon_key(argt, caller_fn) for argt in (getattr(ir, "arguments", []) or [])),
    )

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

# Compute SSA aliases that unambiguously trace back to formal params
def _function_parameter_aliases(fn):
    cached = _PARAMETER_ALIAS_CACHE.get(fn)
    if cached is not None: return cached

    aliases = defaultdict(set)
    for index, candidates in _parameter_variants(fn):
        for parameter in candidates:
            aliases[parameter].add(index)
            aliases[_non_ssa_variable(parameter)].add(index)

    operations = [ir for node in getattr(fn, "nodes", []) for ir in _ssa_irs(node)]
    # Iterate until chained assignments expose every formal parameter origin
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
        index_operations.extend(ir for ir in _ssa_irs(node) if isinstance(ir, Index))

    # Resolve nested index references only after their parent locations become known
    changed = True
    while changed:
        changed = False
        for ir in index_operations:
            base, key, location = ir.variable_left, ir.variable_right, None
            if isinstance(base, ReferenceVariable):
                previous = locations.get(base)
                if isinstance(previous, MappingSlotVar):
                    # base[first][second]
                    nested_key = MappingKeyPath(previous.key_path.components + (canon_key(key, fn),))
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

# Identify mapping-like state vars across Slither type reprs
def _is_mapping_state_variable(var) -> bool:
    if not isinstance(var, StateVariable): return False
    var_type = getattr(var, "type", None)
    type_name = type(var_type).__name__
    type_text = str(var_type).replace(" ", "").lower()
    return (type_name == "MappingType" or type_text.startswith("mapping("))

# Recover persistent-storage locations read and written by CFG block
def _node_storage_accesses(node, reference_locations):
    reads, writes, precise_read_bases, precise_write_bases = set(), set(),set(),set()
    unresolved_read_bases, unresolved_write_bases = set(), set()
    read_targets = reads, precise_read_bases, unresolved_read_bases
    write_targets = writes, precise_write_bases, unresolved_write_bases

    # Record an access and whether its mapping identity is precise
    def record_access(location, targets):
        if location is None: return
        accesses, precise_bases, unresolved_bases = targets
        accesses.add(location)
        if isinstance(location, MappingSlotVar):
            precise_bases.add(location.base)
        elif _is_mapping_state_variable(location):
            unresolved_bases.add(location)

    # Index constructs a storage reference
    for ir in _ssa_irs(node):
        if isinstance(ir, Index):
            key_operand = getattr(ir, "variable_right", None)
            if key_operand is not None:
                record_access(_location_of_read_operand(key_operand, reference_locations), read_targets)
            continue

        # Member and Phi construct or merge values/references
        # Records storage read when resulting reference/value is consumed later
        if isinstance(ir, (Member, Phi)): continue

        # Every state-backed operand consumed by this operation is a read at this block
        for operand in (getattr(ir, "read", []) or []):
            record_access(_location_of_read_operand(operand, reference_locations), read_targets)

        # Persistent state lvalue
        if _is_storage_lvalue(ir):
            location = _location_of_read_operand(getattr(ir, "lvalue", None), reference_locations)
            record_access(location, write_targets)

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
def _origins_for_operand(operand, bid, origins, reference_locations):
    result = set(origins.get(operand, set()))
    location = _location_of_read_operand(operand, reference_locations)
    if location is not None: result.add(ReadEvent(bid, location))
    return result

# Return logical locations carried by one operand plus its direct storage read
def _locations_for_operand(operand, value_locations, reference_locations, include_non_ssa=False):
    result = set(value_locations.get(operand, set()))
    if include_non_ssa:
        result.update(value_locations.get(_non_ssa_variable(operand), set()))
    direct_location = _location_of_read_operand(operand, reference_locations)
    if direct_location is not None: result.add(direct_location)
    return result

# Return whether the operation writes persistent Solidity storage
def _is_storage_lvalue(ir) -> bool:
    if not isinstance(ir, OperationWithLValue): return False

    # These create references/SSA joins but do not perform persistent storage writes
    if isinstance(ir, (Index, Member, Phi)): return False

    lvalue = getattr(ir, "lvalue", None)
    if lvalue is None: return False

    concrete = _non_ssa_variable(lvalue)
    if isinstance(concrete, StateVariable): return True

    if isinstance(lvalue, ReferenceVariable):
        return isinstance(_reference_origin(lvalue), StateVariable)
    return bool(getattr(lvalue, "is_storage", False))

# Capture require/assert even where Slither represents them as a SolidityCall
def _is_control_solidity_call(ir) -> bool:
    if not isinstance(ir, SolidityCall): return False
    function_text = str(getattr(ir, "function", "")).lower()
    return ("require(" in function_text or "assert(" in function_text)

# Internal and library calls are handled through function summaries
def _is_external_effect(ir) -> bool:
    if isinstance(ir, (InternalCall, LibraryCall, EventCall)): return False
    if isinstance(ir, SolidityCall):
        function_text = str(getattr(ir, "function", "")).lower()
        return ("selfdestruct" in function_text or "suicide" in function_text)
    return isinstance(ir, Call)

# Classify IR operations that can consume stale state in a security-relevant way
def _sensitive_operation_kind(ir):
    if isinstance(ir, Condition) or _is_control_solidity_call(ir): return "control"
    if _is_storage_lvalue(ir): return "storage_write"
    if isinstance(ir, HighLevelCall):
        apparent = getattr(ir, "function", None)
        if apparent is not None and is_view_only(apparent): return None
    if _is_external_effect(ir): return "external_effect"
    return None

# Normalize the values returned by different Slither return IR variants
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

# Union influence facts into a map and report whether the map changed.
def _merge_origin_set(mapping, key, values) -> bool:
    if key is None or not values: return False
    before = len(mapping[key])
    mapping[key].update(values)
    return len(mapping[key]) != before

# Compute a function summary using exact origin propagation
def _combined_influence_summary(targets, summaries):
    combined = FunctionInfluenceSummary()
    found = False
    for target in targets:
        summary = summaries.get(target)
        if summary is None: continue
        _merge_function_summary(combined, summary)
        found = True
    return combined if found else None

# Separate physical state reads from formal-parameter influence
def _record_origins(origins, reads, parameters):
    for origin in origins:
        if isinstance(origin, ReadEvent): reads.add(origin)
        elif isinstance(origin, ParameterOrigin): parameters.add(origin.index)

def _analyze_function_influence(fn, keep, summaries, target_resolver=None) -> FunctionInfluenceSummary:
    """Compute parameter, state-read, return, and sink influence for one function"""
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
    returned_locations_by_site: DefaultDict[ReturnSite, set[Hashable]] = defaultdict(set)

    parameters = list(getattr(fn, "parameters_ssa", []) or [])
    if not parameters: parameters = list(getattr(fn, "parameters", []) or [])
    for index, parameter in enumerate(parameters):
        origins[parameter].add(ParameterOrigin(index))

    reference_locations, operations = _function_reference_locations(fn, keep), []
    for node in sorted(getattr(fn, "nodes", []), key=lambda item: item.node_id):
        bid = (function_key(fn), node.node_id)
        if (keep is not None and bid not in keep): continue
        call_ordinal = 0
        for ir_index, ir in enumerate(_ssa_irs(node)):
            is_call = isinstance(ir, (InternalCall, LibraryCall, HighLevelCall))
            callees = (
                tuple(target_resolver(ir, fn))
                if is_call and target_resolver is not None
                else (getattr(ir, "function", None),) if is_call else ()
            )
            operations.append((bid, ir_index, ir, call_ordinal if is_call else None, callees))
            call_ordinal += is_call

    # SSA is ordered, but Phi nodes and recursive summary propagation require a local fixed point
    local_changed = True
    while local_changed:
        local_changed = False
        for bid, ir_index, ir, call_ordinal, callees in operations:
            lvalue = getattr(ir, "lvalue", None)
            produced_return_locations = False

            # Index and Member construct references
            if isinstance(ir, Index):
                derived_origins = set()
                key_operand = getattr(ir, "variable_right", None)
                if key_operand is not None:
                    derived_origins.update(_origins_for_operand(key_operand, bid, origins, reference_locations))
                
                # Only propagate pre-existing origins from the base reference
                base_operand = getattr(ir, "variable_left", None)
                if base_operand is not None: derived_origins.update(origins.get(base_operand, set()))
                if _merge_origin_set(origins, lvalue, derived_origins): local_changed = True
                continue

            if isinstance(ir, Member):
                derived_origins = set()
                for operand in getattr(ir, "read", []) or []: derived_origins.update(origins.get(operand, set()))
                if _merge_origin_set(origins, lvalue, derived_origins): local_changed = True
                continue

            read_origins, read_locations = set(), set()
            for operand in getattr(ir, "read", []) or []:
                read_origins.update(_origins_for_operand(operand, bid, origins, reference_locations))
                read_locations.update(_locations_for_operand(operand, value_locations, reference_locations))

            # Instantiate summaries for all statically resolved calls
            # Internal/library calls are propagation boundaries only.
            # High-level calls are both external-interaction sinks; and summary-bearing return producers when their implementation is known
            if isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
                arguments = list(getattr(ir, "arguments", []) or [])
                argument_origins = [_origins_for_operand(argt, bid, origins, reference_locations) for argt in arguments]
                argument_locations = [_locations_for_operand(argt, value_locations, reference_locations, include_non_ssa=True) for argt in arguments]

                call_key_substitutions = _call_key_substitutions(ir, fn)
                callee_summary = _combined_influence_summary(callees, summaries)
                internal_dispatch = isinstance(ir, (InternalCall, LibraryCall))
                if callee_summary is None:
                    if internal_dispatch:
                        # Unresolved internal/library dispatch: preserve recall
                        for values in argument_origins: sensitive_origins.update(values)
                        continue
                else:
                    callee_sites = (set(callee_summary.sink_reads) | set(callee_summary.sink_parameters))
                    for sink_site in callee_sites:
                        sink_origins[sink_site].update(callee_summary.sink_reads.get(sink_site, set()))
                        for parameter_index in callee_summary.sink_parameters.get(sink_site, set()):
                            if parameter_index < len(argument_origins):
                                sink_origins[sink_site].update(argument_origins[parameter_index])

                    # Reads inside the callee that reaches a callee sink
                    sensitive_origins.update(callee_summary.read_to_sink)

                    # Caller args reaching sensitive callee parameters
                    for parameter_index in (callee_summary.parameter_to_sink):
                        if parameter_index < len(argument_origins):
                            sensitive_origins.update(argument_origins[parameter_index])

                    all_return_indices = (set(callee_summary.read_to_returns) | set(callee_summary.parameter_to_returns) | set(callee_summary.return_locations))

                    all_return_origins, all_return_locations = set(), set()
                    for return_index in sorted(all_return_indices):
                        # Physical reads remain expressed in the callee's own namespace.
                        component_origins = set(callee_summary.read_to_returns.get(return_index,set()))

                        # Logical returned locations are translated into the caller's namespace
                        component_locations = {
                            _instantiate_location_template(location, call_key_substitutions)
                            for location in (callee_summary.return_locations.get(return_index, set()))
                        }

                        for parameter_index in (callee_summary.parameter_to_returns.get(return_index, set())):
                            if parameter_index < len(argument_origins):
                                component_origins.update(argument_origins[parameter_index])
                                component_locations.update(argument_locations[parameter_index])

                        if (not component_origins and not component_locations): continue
                        all_return_origins.update(component_origins)
                        all_return_locations.update(component_locations)

                        if lvalue is not None:
                            if _merge_origin_set(tuple_components[lvalue], return_index, component_origins):
                                local_changed = True
                            if _merge_origin_set(tuple_location_components[lvalue], return_index, component_locations):
                                local_changed = True

                    if _merge_origin_set(origins, lvalue, all_return_origins): local_changed = True
                    if _merge_origin_set(value_locations, lvalue, all_return_locations): local_changed = True
                    produced_return_locations = bool(all_return_locations)
                    if internal_dispatch: continue

            # Preserve individual return-component precision
            if isinstance(ir, Unpack):
                tuple_source = _unpack_source(ir)
                return_index = getattr(ir, "index", None)

                selected_origins, selected_locations = set(), set()
                if (tuple_source is not None and return_index is not None):
                    selected_origins.update(tuple_components[tuple_source].get(return_index, set()))
                    selected_locations.update(tuple_location_components[tuple_source].get(return_index, set()))

                if (not selected_origins and tuple_source is not None):
                    selected_origins.update(origins.get(tuple_source, set()))
                if (not selected_locations and tuple_source is not None):
                    selected_locations.update(value_locations.get(tuple_source, set()))
                if _merge_origin_set(origins, lvalue, selected_origins): local_changed = True
                if _merge_origin_set(value_locations, lvalue, selected_locations): local_changed = True
                continue

            # Unresolved view call produces one receiver/signature/arg-qualified location
            external_getter_origins, external_getter_locations = set(), set()
            if isinstance(ir, HighLevelCall) and not produced_return_locations:
                external_location = external_view_location(ir, fn, (bid, call_ordinal))
                if external_location is not None:
                    external_getter_origins.add(ReadEvent(bid, external_location))
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
                    value_origins = (_origins_for_operand(value, bid, origins, reference_locations))
                    return_origins[return_index].update(value_origins)
                    logical_locations = _locations_for_operand(value, value_locations, reference_locations)

                    returned_locations[return_index].update(logical_locations)
                    summary_site = ReturnSite( block_id=bid, ir_index=ir_index, return_index=return_index)

                    # Collected after the fixed point stabilizes below
                    returned_locations_by_site[summary_site].update(logical_locations)

            # External getter return values begin at the call lvalue
            if external_getter_origins and _merge_origin_set(origins, lvalue, external_getter_origins):
                local_changed = True
            if external_getter_locations and _merge_origin_set(value_locations,lvalue,external_getter_locations):
                local_changed = True

            # Ordinary SSA definition: result = operation(inputs) propagates every input origin into result
            # Do not apply this rule to Call ops as call returns don't always depend on all call args
            if (isinstance(ir, OperationWithLValue) and not _is_storage_lvalue(ir) and (not isinstance(ir, Call) or isinstance(ir, SolidityCall)) and not isinstance(ir, Unpack)):
                if _merge_origin_set(origins, lvalue, read_origins): local_changed = True
                if _merge_origin_set(value_locations, lvalue, read_locations): local_changed = True

    summary = FunctionInfluenceSummary()
    for sink_site, origins_here in sink_origins.items():
        _record_origins(origins_here, summary.sink_reads[sink_site], summary.sink_parameters[sink_site])
    _record_origins(sensitive_origins, summary.read_to_sink, summary.parameter_to_sink)

    for return_index, component_origins in return_origins.items():
        _record_origins(component_origins, summary.read_to_returns[return_index], summary.parameter_to_returns[return_index])

    for (return_index, locations) in returned_locations.items():
        summary.return_locations[return_index].update(locations)
    for return_site, locations in returned_locations_by_site.items():
        summary.return_locations_by_site[return_site].update(locations)
    return summary

# Update one monotone set and report whether it grew
def _update_set(target, values) -> bool:
    before = len(target)
    target.update(values)
    return len(target) != before

# Merge a newly computed influence summary into the fixed-point accumulator
def _merge_function_summary(destination, source) -> bool:
    changed = (_update_set(destination.parameter_to_sink, source.parameter_to_sink) | _update_set(destination.read_to_sink, source.read_to_sink))
    for attribute in ("sink_reads", "sink_parameters", "parameter_to_returns", "read_to_returns", "return_locations", "return_locations_by_site"):
        target_map = getattr(destination, attribute)
        for key, values in getattr(source, attribute).items():
            changed |= _update_set(target_map[key], values)
    return changed

def _compute_function_influence_summaries(functions, keep=None, target_resolver=None):
    """Compute the least interprocedural fixed point of influence facts."""
    summaries = { fn: FunctionInfluenceSummary() for fn in functions }
    changed, rounds = True, 0
    maximum_rounds = max(32, (len(functions) * 8) + 8)
    while changed:
        changed = False
        rounds += 1
        if rounds > maximum_rounds: raise RuntimeError(f"Function influence analysis never converged in {maximum_rounds} rounds")
        for fn in functions:
            candidate = _analyze_function_influence(fn, keep, summaries, target_resolver=target_resolver)
            if _merge_function_summary(summaries[fn], candidate): changed = True
    return summaries

class ICFG:
    """
    Physical block graph and analysis indexes used by MV-Scan
    NOTE: Intraprocedural successors and call-entry edges are separated so no context-insensitive
    synthetic return can enter another caller's CFG.
    """
    def __init__(self):
        self.blocks: Dict[BasicBlock, Dict[str, Set]] = {}
        self.var_reads: Dict[StateVariable, Set[BasicBlock]] = defaultdict(set)
        self.var_writes: Dict[StateVariable, Set[BasicBlock]] = defaultdict(set)
        self.fn_lookup = {}  # function_key(fn) -> Function
        self.fn_returns = {} # Function -> Set[Var]

        # Function -> return index -> exact state
        # locations influencing that returned component.
        self.fn_return_components: Dict[object, Dict[int, Set[object]]] = {}
        self.fn_return_sites: Dict[object, Dict[ReturnSite, Set[object]]] = {}

        self.predecessors: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)
        self.node_lookup: Dict[BasicBlock, Node] = {}

        # Intraprocedural edges remain in blocks[bid]["succ"]
        # Interprocedural calls are stored separately to prevent context-insensitive wrong-caller return edges
        self.call_edges: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)
        self.call_edge_context_modes = {}
        self.call_targets_by_site: dict[CallSiteId, tuple[str, ...]] = {}
        self.call_edges_by_source: DefaultDict[BasicBlock, set[CallEdgeRecord]] = defaultdict(set)
        self.functions_by_contract_and_signature = defaultdict(set)
        self.concrete_functions_by_signature = defaultdict(set)

        self.function_influence_summaries: dict[object, FunctionInfluenceSummary] = {}
        self.sensitive_read_events: set[ReadEvent] = set()
        self.sensitive_locations_by_block: DefaultDict[BasicBlock, set[Hashable]] = defaultdict(set)
        self.sink_reads_by_site: DefaultDict[SinkSite, set[ReadEvent]] = defaultdict(set)
        self.sensitive_read_events_by_owner = defaultdict(set)
        self.sink_sites_by_owner_and_event = defaultdict(set)
        self.function_write_summaries = {}

        # Root-seeding metadata: each physical entry block receives one analysis owner
        self.root_exposures: DefaultDict[str, Set[str]] = defaultdict(set)

        # Reference locations are function-local and independent of root ownership
        self.reference_locations_by_function: Dict[str, Dict[object, object]] = {}

        # Relation pseudo -> block -> exact concrete
        # relation-member locations accessed at that block.
        self.relation_reads: DefaultDict[object, DefaultDict[BasicBlock, Set[object]]] = defaultdict(lambda: defaultdict(set))

        self.relation_writes: DefaultDict[object, DefaultDict[BasicBlock, Set[object]]] = defaultdict(lambda: defaultdict(set))

        self.relation_shadowed_members = defaultdict(set)
        self.relation_unresolved_base_reads = defaultdict(lambda: defaultdict(set))
        self.relation_unresolved_base_writes = defaultdict(lambda: defaultdict(set))
        self.relation_template_reads = defaultdict(lambda: defaultdict(set))
        self.relation_template_writes = defaultdict(lambda: defaultdict(set))

        # Storing all provenance sites
        self.relation_origins: DefaultDict[object, Set[object]] = defaultdict(set)
        self.entry_contexts_by_block = defaultdict(set)
        self.root_function_by_owner = {}
        self.relevant_formals_by_function: dict[str, set[str]] = defaultdict(set)
        self.context_call_parents = defaultdict(set)
        self.contexts_by_call_target = defaultdict(set)
        self.contextual_location_cache = {}
        self.interface_dispatch_enabled = False
        self.max_dispatch_targets = 16

    # Index concrete functions by declaration, signature, and lineage
    def build_resolver_indexes(self) -> None:
        self.functions_by_contract_and_signature.clear()
        self.concrete_functions_by_signature.clear()
        for key in sorted(self.fn_lookup):
            fn = self.fn_lookup[key]
            signature = function_signature_key(fn)
            contract = getattr(fn, "contract_declarer", None)
            self.functions_by_contract_and_signature[(contract, signature)].add(fn)
            if getattr(fn, "entry_point", None) is not None:
                self.concrete_functions_by_signature[signature].add(fn)

    # Find formal parameters that participate in symbolic storage locations
    def compute_relevant_formals(self):
        self.relevant_formals_by_function.clear()

        # Extract every symbolic term carried by a state location
        def templates(location):
            if isinstance(location, MappingSlotVar): return (location.key,)
            if isinstance(location, ExternalStateVar): return (location.addr, *location.args)
            return ()

        for bid, info in self.blocks.items():
            for location in set(info.get("reads", set())) | set(info.get("writes", set())):
                for template in templates(location):
                    self.relevant_formals_by_function[bid[0]].update(_ARG_PATTERN.findall(str(template)))
        for fn, component_map in self.fn_return_components.items():
            fn_key = function_key(fn)
            for locations in component_map.values():
                for location in locations:
                    for template in templates(location):
                        self.relevant_formals_by_function[fn_key].update(_ARG_PATTERN.findall(str(template)))

        # Push callee key reqs backward so callers retain only relevant bindings
        changed = True
        while changed:
            changed = False
            for edges in self.call_edges_by_source.values():
                for edge in edges:
                    target_relevant = self.relevant_formals_by_function.get(edge.target_function_key, set())
                    caller_relevant = self.relevant_formals_by_function[edge.source_bid[0]]
                    before = len(caller_relevant)
                    for placeholder, template in edge.substitutions:
                        if placeholder in target_relevant: caller_relevant.update(_ARG_PATTERN.findall(template))
                    changed |= len(caller_relevant) != before

    # Instantiate a symbolic state location for a concrete execution context
    def contextualize_location(self, location, context: ExecutionContext):
        active_sender = context.active_sender or f"@sender::{context.owner}"
        cache_key = (location, context.owner, context.bindings, active_sender)
        cached = self.contextual_location_cache.get(cache_key)
        if cached is not None: return cached
        if isinstance(location, MappingSlotVar):
            instantiated = MappingSlotVar(location.base, instantiate_key_template(location.key, context.binding_map, active_sender))
        elif isinstance(location, ExternalStateVar):
            instantiated = ExternalStateVar(
                location.selector,
                instantiate_key_template(location.addr, context.binding_map, active_sender),
                tuple(instantiate_key_template(argument, context.binding_map, active_sender) for argument in location.args),
            )
        else:
            instantiated = location
        self.contextual_location_cache[cache_key] = instantiated
        return instantiated

    def resolve_call_functions(self, ir, caller_fn) -> tuple:
        """Resolve a call to bounded canonical physical function objects."""
        direct = getattr(ir, "function", None)
        if function_has_body(direct):
            canonical_direct = self.fn_lookup.get(function_key(direct))
            if function_has_body(canonical_direct): return (canonical_direct,)

        signature = _call_signature_key(ir)
        caller_contract = getattr(caller_fn, "contract_declarer", None)
        if isinstance(ir, InternalCall):
            lineage = contract_lineage(caller_contract)
            candidates = sorted({
                fn for fn in self.concrete_functions_by_signature.get(signature, set())
                if function_has_body(fn)
                and getattr(fn, "contract_declarer", None) in lineage
            }, key=function_key)
            return tuple(candidates) if len(candidates) == 1 else ()

        if isinstance(ir, LibraryCall):
            library_contract = (receiver_contract_type(ir) or getattr(direct, "contract_declarer", None))
            candidates = sorted({
                fn for fn in self.functions_by_contract_and_signature.get((library_contract, signature), set())
                if function_has_body(fn)
            }, key=function_key)
            return tuple(candidates) if len(candidates) == 1 else ()

        if not (self.interface_dispatch_enabled and isinstance(ir, HighLevelCall)): return ()

        receiver_contract = receiver_contract_type(ir)
        if (
            receiver_contract is not None
            and not bool_attr(receiver_contract, "is_interface")
            and not bool_attr(receiver_contract, "is_abstract")
        ):
            visible_functions = sorted({
                fn for fn in (getattr(receiver_contract, "functions", []) or [])
                if function_has_body(fn)
                and function_signature_key(fn) == signature
            }, key=function_key)
            if len(visible_functions) == 1: return tuple(visible_functions)
            exact = sorted({
                fn for fn in self.concrete_functions_by_signature.get(signature, set())
                if function_has_body(fn)
                and getattr(fn, "contract_declarer", None) is receiver_contract
            }, key=function_key)
            return tuple(exact) if len(exact) == 1 else ()

        apparent_contract = (getattr(direct, "contract_declarer", None) or getattr(direct, "contract", None) or receiver_contract)
        if apparent_contract is None or declaration_is_dependency(apparent_contract): return ()
        candidates = sorted({
            fn for fn in self.concrete_functions_by_signature.get(signature, set())
            if function_has_body(fn)
            and not declaration_is_dependency(fn)
            and apparent_contract in contract_lineage(getattr(fn, "contract_declarer", None) or getattr(fn, "contract", None))
        }, key=function_key)
        if len(candidates) > self.max_dispatch_targets: return ()
        return tuple(candidates)

    # Construct reverse intraprocedural CFG once
    def rebuild_predecessors(self):
        self.predecessors.clear()
        for source_bid, info in self.blocks.items():
            for destination_bid in info.get("succ", set()):
                if destination_bid in self.blocks: self.predecessors[destination_bid].add(source_bid)

    # Return ordinary intraprocedural CFG successors or call-entry successors for a block
    def cfg_successors(self, bid: BasicBlock): return set(self.blocks.get(bid, {}).get("succ", set()))
    def call_successors(self, bid: BasicBlock): return set(self.call_edges.get(bid, set()))

    # May-reachability relation: (i) CFG continuation remains reachable after call; (ii) resolved callee body as well
    def reachability_successors(self, bid: BasicBlock): return self.cfg_successors(bid) | self.call_successors(bid)

    def compute_sensitive_read_events(self, keep):
        """Compute global and owner-specific state-read-to-sink indexes."""
        functions_by_key = { function_key(fn): fn for fn in self.fn_lookup.values() }
        functions = [ functions_by_key[key] for key in sorted(functions_by_key)]
        summaries = (_compute_function_influence_summaries(functions, keep=keep, target_resolver=lambda ir, caller: tuple(self.resolve_call_functions(ir, caller))))

        self.function_influence_summaries = (summaries)
        self.sensitive_read_events.clear()
        self.sensitive_locations_by_block.clear()
        self.sink_reads_by_site.clear()

        # Merge function-local summaries into the compilation-wide sensitive-read index
        for summary in summaries.values():
            self.sensitive_read_events.update(summary.read_to_sink)
            for sink_site, events in summary.sink_reads.items():
                self.sink_reads_by_site[sink_site].update(events)

        for event in self.sensitive_read_events:
            self.sensitive_locations_by_block[event.block_id].add(event.location)

        self.sensitive_read_events_by_owner.clear()
        self.sink_sites_by_owner_and_event.clear()
        # Retain root-specific sink evidence so unrelated entry paths cannot justify a finding
        for owner, root_fn in self.root_function_by_owner.items():
            summary = self.function_influence_summaries.get(root_fn)
            if summary is None: continue
            self.sensitive_read_events_by_owner[owner].update(summary.read_to_sink)
            for sink_site, events in summary.sink_reads.items():
                for event in events:
                    self.sink_sites_by_owner_and_event[(owner, event)].add(sink_site)

    def compute_function_write_summaries(self, keep):
        """Compute interprocedural may-write and conservative must-write summaries."""
        functions = sorted(set(self.fn_lookup.values()), key=function_key)
        summaries = { fn: FunctionWriteSummary() for fn in functions }

        # Phase 1: monotone may-write summaries
        changed = True
        while changed:
            changed = False
            for fn in functions:
                may_writes = set()
                for node in getattr(fn, "nodes", []) or []:
                    bid = (function_key(fn), node.node_id)
                    if bid not in keep or bid not in self.blocks: continue
                    may_writes.update(self.blocks[bid]["writes"])
                    for ir in _ssa_irs(node):
                        if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)): continue
                        substitutions = _call_key_substitutions(ir, fn)
                        target_may_sets = []
                        for callee in self.resolve_call_functions(ir, fn):
                            callee_summary = summaries.get(callee)
                            if callee_summary is None: continue
                            target_may_sets.append({ _instantiate_location_template(location, substitutions) for location in callee_summary.may_writes })
                        if target_may_sets: may_writes.update(set().union(*target_may_sets))
                if not may_writes.issubset(summaries[fn].may_writes):
                    summaries[fn].may_writes.update(may_writes)
                    changed = True

        # Phase 2: greatest fixed point for must writes
        for fn in functions: summaries[fn].must_writes = set(summaries[fn].may_writes)

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
                    entry_bid = ((function_key(fn), fn.entry_point.node_id) if getattr(fn, "entry_point", None) is not None else None)

                    local_changed = True
                    while local_changed:
                        local_changed = False
                        for node in sorted(nodes, key=lambda item: item.node_id):
                            bid = (function_key(fn), node.node_id)
                            predecessors = self.predecessors.get(bid, set()) & bids
                            if bid == entry_bid or not predecessors:
                                incoming = set()
                            else:
                                incoming = set.intersection(*(out_sets[pred] for pred in predecessors))
                            generated = set(self.blocks[bid]["writes"])
                            for ir in _ssa_irs(node):
                                if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)): continue
                                substitutions = _call_key_substitutions(ir, fn)
                                target_must_sets = []
                                for callee in self.resolve_call_functions(ir, fn):
                                    callee_summary = summaries.get(callee)
                                    if callee_summary is None: continue
                                    target_must_sets.append({
                                        _instantiate_location_template(location, substitutions)
                                        for location in callee_summary.must_writes
                                    })
                                if target_must_sets:
                                    generated.update(set.intersection(*target_must_sets))
                            new_out = incoming | generated
                            if new_out != out_sets[bid]:
                                out_sets[bid] = new_out
                                local_changed = True

                    exits = [
                        (function_key(fn), node.node_id)
                        for node in nodes
                        if not any((function_key(fn), son.node_id) in bids for son in (getattr(node, "sons", []) or []))
                        and str(getattr(node, "type", "")).lower() not in {"throw", "revert"}
                    ]
                    candidate = (set.intersection(*(out_sets[bid] for bid in exits)) if exits else set())
                if candidate != summaries[fn].must_writes:
                    summaries[fn].must_writes = candidate
                    changed = True

        self.function_write_summaries = summaries

    # Return relation-member locations at this block that reach a sensitive operation
    def sensitive_relation_reads(self, bid, relation):
        relation_locations = self.relation_reads.get(relation, {}).get(bid, set())
        sensitive_locations = self.sensitive_locations_by_block.get(bid, set())
        return {
            location for location in relation_locations
            if any(location_matches_member(sensitive, location) for sensitive in sensitive_locations)
        }

    # Return whether the exact read block and state location reaches a sensitive operation
    def read_event_is_sensitive(self, bid, var, context=None) -> bool:
        if context is not None:
            events = { event for event in self.sensitive_read_events_by_owner.get(context.owner, set()) if event.block_id == bid }
            if not events: return False
            observed = [ self.contextualize_location(event.location, context) for event in events ]
            members = getattr(var, "vars", None)
            expected = members if members is not None else (var,)
            for location in observed:
                for member in expected:
                    bindings, constraints = {}, set()
                    compatible = _contextual_member_match(location, member, bindings, constraints)
                    if compatible: return True
            return False
        locations = (self.sensitive_locations_by_block.get(bid, set()))

        if not locations: return False
        if getattr(var, "vars", None) is not None: return bool(self.sensitive_relation_reads(bid, var))
        return any(location_matches_member(location, var) for location in locations)

    def precompute_return_summaries(self, functions):
        """Compute ordinary return locations independently of relation ablation."""
        self.fn_returns.clear()
        self.fn_return_components.clear()
        self.fn_return_sites.clear()

        summaries = _compute_function_influence_summaries(functions, keep=None, target_resolver=self.resolve_call_functions)
        for fn in functions:
            # Preserve restriction: relation-return helpers must not mutate persistent state
            if any(
                any(isinstance(variable, StateVariable) for variable in node.variables_written)
                or any(_is_storage_lvalue(ir) for ir in _ssa_irs(node))
                for node in fn.nodes
            ):
                continue

            summary = summaries[fn]
            component_locations = { return_index: set(locations) for return_index, locations in summary.return_locations.items() if locations }
            if not component_locations: continue
            self.fn_return_components[fn] = component_locations
            self.fn_returns[fn] = set().union(*component_locations.values())
            if ENABLE_MULTI_RETURN_GROUPS:
                site_locations = { site: set(locations) for site, locations in summary.return_locations_by_site.items() if locations }
                if site_locations: self.fn_return_sites[fn] = site_locations

    def add_block(self, node: Node):
        """Materialize one physical Slither CFG node and update ICFG indexes."""
        block_id: BasicBlock = (function_key(node.function), node.node_id)
        fn = node.function

        # Already processed
        if block_id in self.blocks: return
        self.node_lookup[block_id] = node

        # Gather storage reads and writes
        legacy_reads = { v for v in (getattr(node, "variables_read", []) or []) if isinstance(v, StateVariable) }
        legacy_writes = { v for v in (getattr(node, "variables_written", []) or []) if isinstance(v, StateVariable) }

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
            # Remove coarse node-level base mapping only when every observed access to that base was precisely reconstructed
            for base in precise_read_bases:
                if base not in unresolved_read_bases: reads.discard(base)
            for base in precise_write_bases:
                if base not in unresolved_write_bases: writes.discard(base)

        # Add exact slots, scalar state accesses, and any unresolved base mapping fallback
        reads.update(ir_reads)
        writes.update(ir_writes)

        # Intra-procedural successors
        succ: Set[BasicBlock] = { (function_key(s.function), s.node_id) for s in node.sons }

        # Handle every call IR in this block
        for callsite_id, ir in iter_call_sites(node):
            # Call-graph edges could be Function, None, or Variable
            resolved_functions = self.resolve_call_functions(ir, fn)
            resolved_targets = tuple(function_key(callee) for callee in resolved_functions)
            self.call_targets_by_site[callsite_id] = resolved_targets

            for callee in resolved_functions:
                entry_bid = (function_key(callee), callee.entry_point.node_id)

                # Call edge separated from ordinary CFG continuation
                self.call_edges[block_id].add(entry_bid)
                if isinstance(ir, (InternalCall, LibraryCall)):
                    edge_mode = ("preserve", None)
                else:
                    target_contract = (getattr(callee, "contract", None) or getattr(callee, "contract_declarer", None))
                    edge_mode = ("switch", contract_storage_key(target_contract))
                edge_key = (block_id, entry_bid)
                previous_mode = self.call_edge_context_modes.get(edge_key)
                if previous_mode is not None and previous_mode != edge_mode:
                    raise RuntimeError(f"Conflicting storage-context semantics for call edge {edge_key}: {previous_mode} vs {edge_mode}")
                self.call_edge_context_modes[edge_key] = edge_mode
                self.call_edges_by_source[block_id].add(
                    CallEdgeRecord(
                        source_bid=block_id,
                        target_bid=entry_bid,
                        callsite_id=callsite_id,
                        target_function_key=function_key(callee),
                        storage_mode=edge_mode[0],
                        target_storage_context=edge_mode[1],
                        substitutions=tuple(sorted((f"$arg{index}", canon_key(argument, fn)) for index, argument in enumerate(getattr(ir, "arguments", []) or []))),
                    )
                )
            # Summarize concrete returns; otherwise abstract an unresolved view
            instantiated_returns = set()
            for callee in resolved_functions:
                if callee in self.fn_returns:
                    instantiated_returns.update(_subst_returns_with_args(callee, ir, self.fn_returns[callee], fn))
            reads.update(instantiated_returns)
            if not instantiated_returns:
                external_location = external_view_location(ir, fn, callsite_id)
                if external_location is not None: reads.add(external_location)

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

# Build exact member-to-member evidence for a writer/reader block pair
def _relation_access_evidence(icfg, relation, writer_bid, reader_bid):
    writer_locations = (icfg.relation_writes.get(relation, {}).get(writer_bid, set()))
    reader_locations = icfg.sensitive_relation_reads(reader_bid, relation)
    if not writer_locations or not reader_locations: return ()
    evidence_set = set()
    for writer_location in sorted(writer_locations, key=state_entity_sort_key):
        writer_members = matching_relation_members(relation.vars, writer_location)
        for reader_location in sorted(reader_locations, key=state_entity_sort_key):
            reader_members = matching_relation_members(relation.vars, reader_location)
            for writer_member in writer_members:
                for reader_member in reader_members:
                    if writer_member == reader_member: continue
                    evidence_set.add(RelationAccessEvidence(
                        writer_location=writer_location,
                        writer_member=writer_member,
                        reader_location=reader_location,
                        reader_member=reader_member,
                    ))
    return tuple(sorted(evidence_set, key=repr))

# Check whether a block has exact or symbolic access to a relation
def candidate_access(icfg, relation, bid, kind: str) -> bool:
    exact_map = (icfg.relation_writes if kind == "write" else icfg.relation_reads)
    template_map = (icfg.relation_template_writes if kind == "write" else icfg.relation_template_reads)
    return bool(exact_map.get(relation, {}).get(bid, set()) or template_map.get(relation, {}).get(bid, set()))

# Split canonical nested-mapping keys into independently unifiable components
def split_key_path(key: str): return tuple(str(key).split("]["))

# Identify relation-level sender and argument placeholders
def _is_relation_placeholder(term: str) -> bool: return term == "$sender" or bool(re.fullmatch(r"\$arg\d+", term))

# Identify constants and state references that cannot vary by transaction
def _is_fixed_term(term: str) -> bool: return term.startswith(("@const::", "@state::", "@contract::"))

# Identify transaction-scoped terms that may require equality constraints
def _is_free_runtime_term(term: str) -> bool: return term.startswith(("@txarg::", "@sender::"))

# Identify terms whose provenance is too imprecise for safe unification
def _is_opaque_term(term: str) -> bool: return term.startswith(("@local::", "@unknown::"))

# Construct an ordered equality constraint
def _constraint(left: str, right: str):
    first, second = sorted((left, right))
    return KeyEqualityConstraint(first, second)

# Unify one expected/observed key component while accumulating constraints
def _unify_component(expected, observed, bindings, constraints) -> bool:
    if expected == observed: return True
    if _is_relation_placeholder(expected):
        previous = bindings.get(expected)
        if previous is None:
            bindings[expected] = observed
            return not (_is_opaque_term(observed) or _is_relation_placeholder(observed))
        if previous == observed: return True
        if (
            _is_opaque_term(previous)
            or _is_opaque_term(observed)
            or _is_relation_placeholder(previous)
            or _is_relation_placeholder(observed)
        ):
            return False
        if _is_fixed_term(previous) and _is_fixed_term(observed): return False
        constraints.add(_constraint(previous, observed))
        return True
    if (_is_opaque_term(expected) or _is_opaque_term(observed) or _is_relation_placeholder(observed)):
        return False
    if _is_fixed_term(expected) and _is_fixed_term(observed):
        return False
    if (_is_fixed_term(expected) or _is_fixed_term(observed) or _is_free_runtime_term(expected) or _is_free_runtime_term(observed)):
        constraints.add(_constraint(expected, observed))
        return True
    return False

# Unify complete nested key paths component by component
def _unify_key(expected, observed, bindings, constraints):
    expected_parts, observed_parts = split_key_path(expected), split_key_path(observed)
    if len(expected_parts) != len(observed_parts): return False
    return all(_unify_component(left, right, bindings, constraints) for left, right in zip(expected_parts, observed_parts))

# Match a contextualized location to a relation member
def _contextual_member_match(location, member, bindings, constraints) -> bool:
    if location == member: return True
    if isinstance(location, MappingSlotVar) and isinstance(member, MappingSlotVar):
        if location.base != member.base: return False
        return _unify_key(str(member.key), str(location.key), bindings, constraints)
    if isinstance(location, ExternalStateVar) and isinstance(member, ExternalStateVar):
        if location.selector != member.selector or len(location.args) != len(member.args):
            return False
        pairs = [(member.addr, location.addr), *zip(member.args, location.args)]
        return all(_unify_key(str(expected), str(observed), bindings, constraints) for expected, observed in pairs)
    return False

def contextual_relation_access_evidence(icfg, relation, writer_bid, writer_context, reader_bid, reader_context):
    """
    Match distinct relation-member accesses under execution contexts.

    Matching is existential and edge-local: every writer/reader access edge
    carries its own equality constraints. MV-Scan does not solve one globally
    joint constraint system for all accesses in a candidate; manual validation
    determines whether the surviving contexts are jointly feasible.
    """
    writer_locations = (
        set(icfg.relation_writes.get(relation, {}).get(writer_bid, set()))
        | set(icfg.relation_template_writes.get(relation, {}).get(writer_bid, set()))
    )
    reader_locations = (
        set(icfg.relation_reads.get(relation, {}).get(reader_bid, set()))
        | set(icfg.relation_template_reads.get(relation, {}).get(reader_bid, set()))
    )
    evidence = set()
    for writer_template in sorted(writer_locations, key=state_entity_sort_key):
        writer_location = icfg.contextualize_location(writer_template, writer_context)
        for reader_template in sorted(reader_locations, key=state_entity_sort_key):
            reader_location = icfg.contextualize_location(reader_template, reader_context)
            for writer_member in relation.vars:
                for reader_member in relation.vars:
                    if writer_member == reader_member: continue
                    bindings, constraints = {}, set()
                    writer_ok = _contextual_member_match(writer_location, writer_member, bindings, constraints)
                    if not writer_ok: continue
                    reader_ok = _contextual_member_match(reader_location, reader_member, bindings, constraints)
                    if not reader_ok: continue
                    evidence.add(RelationAccessEvidence(
                        writer_location,
                        writer_member,
                        reader_location,
                        reader_member,
                        tuple(sorted(constraints, key=lambda item: (item.left, item.right))),
                    ))
    return tuple(sorted(evidence, key=lambda item: (
        state_entity_sort_key(item.writer_location),
        state_entity_sort_key(item.writer_member),
        state_entity_sort_key(item.reader_location),
        state_entity_sort_key(item.reader_member),
        tuple((constraint.left, constraint.right)
              for constraint in item.key_constraints),
    )))

def effective_relation_write_members(icfg, relation, writer_bid, writer_context=None):
    writer_locations = (
        set(icfg.relation_writes.get(relation, {}).get(writer_bid, set()))
        | set(icfg.relation_template_writes.get(relation, {}).get(writer_bid, set()))
    )
    writer_fn = icfg.fn_lookup.get(writer_bid[0])
    writer_node = node_by_id(writer_fn, writer_bid[1]) if writer_fn is not None else None
    effective = set()
    for template in writer_locations:
        if NOOP_WRITE_FILTER and writer_node is not None and is_self_copy_write(template, writer_node):
            continue
        location = (
            icfg.contextualize_location(template, writer_context)
            if writer_context is not None else template
        )
        if writer_context is None:
            effective.update(matching_relation_members(relation.vars, location))
            continue
        for member in relation.vars:
            if _contextual_member_match(location, member, {}, set()): effective.add(member)
    return frozenset(effective)

def sensitive_relation_member_events(icfg, relation, reader_bid, reader_context):
    result = defaultdict(set)
    for event in icfg.sensitive_read_events_by_owner.get(reader_context.owner, set()):
        if event.block_id != reader_bid: continue
        location = icfg.contextualize_location(event.location, reader_context)
        for member in relation.vars:
            if _contextual_member_match(location, member, {}, set()): result[member].add(event)
    return result

# Check whether a block overwrites an entity or any member of a relation
def _block_writes_entity(icfg, bid, var) -> bool:
    writes = (icfg.blocks.get(bid, {}).get("writes", set()))
    if var in writes: return True

    members = getattr(var, "vars", None)
    if members is None: return False
    return any(location_matches_member(written_location, member) for written_location in writes for member in members)

# Return whether dst is reachable from src within the same function without an intervening overwrite of var.
def same_function_reachable_without_overwrite(icfg: ICFG, src_bid: BasicBlock, dst_bid: BasicBlock, var) -> bool:
    if src_bid == dst_bid: return True
    if src_bid[0] != dst_bid[0]: return False

    seen, queue = {src_bid}, deque([src_bid])
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

# Returns iff dst_bid is reachable from src_bid without passing through a block writing `v` (other than src)
def reachable_without_overwrite(icfg: ICFG, src_bid, dst_bid, v) -> bool:
    # If the read happens in a block that is itself a branch/ext-call sink
    if src_bid == dst_bid: return True

    seen, q = {src_bid}, deque([src_bid])
    while q:
        cur = q.popleft()
        for nxt in icfg.reachability_successors(cur):
            if nxt == dst_bid: return True                # Reached target
            if nxt in seen: continue                      # Already visited
            if _block_writes_entity(icfg,nxt,v): continue # Overwrote v, continue
            seen.add(nxt); q.append(nxt)
    return False

def stale_read_pairs(icfg: ICFG, reader_filter=None, pair_stats=None, contextual_relations=False):
    """Enumerate coarse physical writer/reader opportunities for later validation."""
    pair_stats = pair_stats if pair_stats is not None else defaultdict(int)
    variables = sorted(icfg.var_writes.keys(), key=state_entity_sort_key)
    for var in variables:
        if var is None: continue
        pair_stats["variables_considered"] += 1
        
        # Canonical MV mode analyzes semantic relations; omits SV
        is_relation = getattr(var, "vars", None) is not None
        if not is_relation and not INCLUDE_SCALAR_WITNESSES:
            pair_stats["scalar_variables_skipped"] += 1
            continue
        if isinstance(var, StateVariable) and is_const(var): continue

        writes = { w_bid for w_bid in icfg.var_writes.get(var, set()) if not icfg.fn_lookup[w_bid[0]].is_constructor }
        if not writes: continue
        reads = { r_bid for r_bid in icfg.var_reads.get(var, set()) if not icfg.fn_lookup[r_bid[0]].is_constructor }
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
            writer_slot_keys = { writer_bid: slot_keys_at(icfg, writer_bid, "writes") for writer_bid in eligible_writers }
            reader_slot_keys = { reader_bid: slot_keys_at(icfg, reader_bid, "reads") for reader_bid in eligible_readers }

        # Evaluate full static writer & sensitive-reader product for this logical state subject
        for writer_bid in eligible_writers:
            for reader_bid in eligible_readers:
                pair_stats["raw_block_pairs"] += 1
                # Skip only the literal same static block
                if writer_bid == reader_bid:
                    pair_stats["same_static_block_filtered"] += 1
                    continue

                relation_evidence = ()
                if is_relation:
                    if contextual_relations:
                        if not (candidate_access(icfg, var, writer_bid, "write") and candidate_access(icfg, var, reader_bid, "read")):
                            pair_stats["relation_incompatible"] += 1
                            continue
                    else:
                        relation_evidence = _relation_access_evidence(icfg, var, writer_bid, reader_bid)
                        if not relation_evidence:
                            pair_stats["relation_incompatible"] += 1
                            continue
                        pair_stats["relation_evidence_edges"] += len(relation_evidence)

                if (REQUIRE_SAME_SLOT_KEY and not is_relation):
                    writer_keys, reader_keys = writer_slot_keys[writer_bid], reader_slot_keys[reader_bid]
                    common_bases = (set(writer_keys) & set(reader_keys))
                    if (common_bases and not any(writer_keys[base] & reader_keys[base] for base in common_bases)):
                        pair_stats["same_slot_key_filtered"] += 1
                        continue

                if writer_bid[0] != reader_bid[0]:
                    writer_reaches_reader, reader_reaches_writer = False, False
                else:
                    writer_reaches_reader = same_function_reachable_without_overwrite(icfg, writer_bid, reader_bid, var)
                    reader_reaches_writer = same_function_reachable_without_overwrite(icfg, reader_bid, writer_bid, var)
                yield RawStateWitness(
                    writer_bid=writer_bid,
                    reader_bid=reader_bid,
                    variable=var,
                    writer_reaches_reader=(writer_reaches_reader),
                    reader_reaches_writer=(reader_reaches_writer),
                    relation_evidence=relation_evidence,
                )