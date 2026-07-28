"""
MV-Scan (Multi-Variable State-Inconsistency Detection)

Goals:
- Build an ICFG over the compilation and its storage layout.
- Keep only the CFG blocks that are reachable from user-callable entrypoints.
- Detect the stale-read/destructive-write pattern and group entangled variables instead of just the primary variable.
- Bucket by transaction-sets and variables so that we can track multi-variable groupings.
- Emit stable JSON for a future dynamic exploit generator (future work).

Non-goals:
- We do not attempt to perfectly catch SI bugs or improve static SV-SI detection.

Extensions:
- Storage-slot aliasing (eliminates FP where unique variables share slots).
- Pseudo-variables for branch-groups and multi-returns (to track MV-SI).
- Reentrant and shared-callee shape tags to guide validation/fuzzing.
- A basic “atomic group” merging of entrypoints (to support above-transaction work).

Usage:
1. Add storageLayout to the configuration of the analyzed codebase to track slots.
2. Run npx hardhat clean && npx hardhat compile on the new configuration.
3. Use ISD_JSON_OUT=out.json slither . --detect inconsistent_state --hardhat-ignore-compile
3a. ISD_JSON_OUT is the filename of the JSON output.
3b. --hardhat-ignore-compile skips npx hardhat clean/compile, which is crucial if you want the detector to pick up slots.
"""
import importlib.metadata
import json, os, glob, pathlib, platform, subprocess, sys
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from typing import List, Set, Dict, Tuple
from collections import defaultdict, deque
from eth_utils import keccak
from eth_abi import encode
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output
from slither.core.variables import StateVariable
from slither.core.declarations.function_contract import FunctionContract
from slither.core.source_mapping.source_mapping import Source
from slither.slithir.operations import HighLevelCall, InternalCall, Assignment
from .utils import alias as alias_module
from .utils import icfg as icfg_module
from .utils.icfg import (
    ICFG, stale_read_pairs, BasicBlock, ExternalStateVar, MappingSlotVar,
    branch_types, reachable_without_overwrite, var_key_txt, function_key, source_file_key,
    ENABLE_MULTIVAR_GROUPS, ENABLE_BRANCH_GROUPS, ENABLE_MULTI_RETURN_GROUPS, relation_member_base, relation_member_is_eligible,
    location_matches_member, matching_relation_members,
    reset_icfg_analysis_caches
)
from .utils.mvscan_env import (
    env_bool, env_csv, env_enum, reject_unknown_prefixed_environment,
)

# Parses DIVERGENCE_BUDGET (0: no traversal | 0<n<inf bounds to n | None: unbounded)
def _parse_divergence_budget():
    raw = os.getenv("DIVERGENCE_BUDGET", "1000").strip().lower()
    if raw in {"inf", "infinite", "unlimited", "unbounded"}:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"DIVERGENCE_BUDGET must be an integer or 'unbounded', got {raw!r}"
        ) from exc
    return None if value < 0 else value

### Global caches and configuration options

# Excluded from seeding
_ROOT_TEST_PATH_MARKERS = (
    "/test/",
    "/tests/",
    "/contracts/test/",
    "/contracts/tests/",
    "/contracts/testing/",
    "/contracts/mock/",
    "/contracts/mocks/",
    "/contracts/fixture/",
    "/contracts/fixtures/",
    "/contracts/harness/",
    "/contracts/harnesses/",
)

# Contract cache ({var_name, storage_slot}) populated with build-info
LAYOUT_CACHE: dict[str, dict[str, int]] = {}

# Helpful ablation flags
DIVERGENCE_BUDGET = _parse_divergence_budget() # Cap forward-slice by CFG nodes (DivertScan §4.2.3 extension)
USER_CALLABLE_ALWAYS: Set[str] = set(env_csv("USER_CALLABLE_ALWAYS"))
USER_CALLABLE_DENY: Set[str] = set(env_csv("USER_CALLABLE_DENY"))
USER_CALLABLE_INCLUDE_ROLE_GATED = env_bool("USER_CALLABLE_INCLUDE_ROLE_GATED", False)
INIT_ONLY_FILTER = env_bool("INIT_ONLY_FILTER", True)
ADMIN_WRITES_BENIGN = env_bool("ADMIN_WRITES_BENIGN", True)
ADMIN_ONLY = set()
COARSE_DEDUP = env_bool("COARSE_DEDUP", True)
ATOMIC_GROUP = env_csv("ATOMIC_GROUP")
MERGE_OVERLOADS = env_bool("MERGE_OVERLOADS", False)
ISD_JSON_OUT = os.getenv("ISD_JSON_OUT")
MVSCAN_STRICT_CONFIG = env_bool("MVSCAN_STRICT_CONFIG", True)
MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS = env_bool(
    "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS", False
)
_KNOWN_MVSCAN_ENV = {
    "MVSCAN_STRICT_CONFIG",
    "MVSCAN_ABLATION",
    "MVSCAN_INCLUDE_SCALAR_WITNESSES",
    "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS",
}

### Value-influence sink test

# Sink behavior choices used in ablation testing:
#   "value"  -> value-influence sink (second iteration)
#   "samevar"-> same-var reread at branch/external-call (first iteration)
#   else     -> skip sink altogether (default)
SINK_TEST = env_enum("SINK_TEST", "none", {"none", "samevar", "value"})

MVSCAN_JSON_SCHEMA_VERSION = 2


@dataclass
class _JsonRunState:
    output_path: Path
    units: dict[str, dict] = field(default_factory=dict)


_JSON_RUNS: dict[tuple[int, str], _JsonRunState] = {}


@dataclass(frozen=True, slots=True)
class FindingWitnessRecord:
    subject: object
    writer_bid: BasicBlock
    reader_bid: BasicBlock
    writer_owner: str
    writer_storage_context: str
    reader_owner: str
    reader_storage_context: str
    operation_pattern: str
    writer_file: str
    writer_line: int
    reader_file: str
    reader_line: int
    relation_evidence: tuple = ()


def effective_config() -> dict:
    return {
        "MVSCAN_ABLATION": icfg_module.MVSCAN_ABLATION,
        "MVSCAN_INCLUDE_SCALAR_WITNESSES": icfg_module.INCLUDE_SCALAR_WITNESSES,
        "MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS": MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS,
        "DIVERGENCE_BUDGET": DIVERGENCE_BUDGET,
        "USER_CALLABLE_ALWAYS": sorted(USER_CALLABLE_ALWAYS),
        "USER_CALLABLE_DENY": sorted(USER_CALLABLE_DENY),
        "USER_CALLABLE_INCLUDE_ROLE_GATED": USER_CALLABLE_INCLUDE_ROLE_GATED,
        "INIT_ONLY_FILTER": INIT_ONLY_FILTER,
        "ADMIN_WRITES_BENIGN": ADMIN_WRITES_BENIGN,
        "COARSE_DEDUP": COARSE_DEDUP,
        "SINK_TEST": SINK_TEST,
        "ATOMIC_GROUP": sorted(ATOMIC_GROUP),
        "MERGE_OVERLOADS": MERGE_OVERLOADS,
        "PROMOTE_MAPPING_BASE": icfg_module.PROMOTE_MAPPING_BASE,
        "NOOP_WRITE_FILTER": icfg_module.NOOP_WRITE_FILTER,
        "REQUIRE_SAME_SLOT_KEY": icfg_module.REQUIRE_SAME_SLOT_KEY,
        "MAPPING_MODE": icfg_module.MAPPING_MODE,
        "ENABLE_MULTIVAR_GROUPS": icfg_module.ENABLE_MULTIVAR_GROUPS,
        "ENABLE_BRANCH_GROUPS": icfg_module.ENABLE_BRANCH_GROUPS,
        "ENABLE_MULTI_RETURN_GROUPS": icfg_module.ENABLE_MULTI_RETURN_GROUPS,
        "ENABLE_EXTERNAL_STATE": icfg_module.ENABLE_EXTERNAL_STATE,
    }


def _sha256_file(path: str | None) -> str | None:
    if not path:
        return None
    file_path = Path(path)
    return sha256(file_path.read_bytes()).hexdigest() if file_path.is_file() else None


def detector_metadata() -> dict:
    try:
        slither_version = importlib.metadata.version("slither-analyzer")
    except importlib.metadata.PackageNotFoundError:
        slither_version = None
    return {
        "name": "MV-Scan",
        "schema_version": MVSCAN_JSON_SCHEMA_VERSION,
        "python_version": platform.python_version(),
        "slither_version": slither_version,
        "source_hashes": {
            "inconsistent_state": _sha256_file(__file__),
            "icfg": _sha256_file(icfg_module.__file__),
            "alias": _sha256_file(alias_module.__file__),
        },
    }


def _analysis_run_token(detector) -> int:
    slither_obj = getattr(detector, "slither", None)
    if slither_obj is not None:
        return id(slither_obj)
    crytic_compile = getattr(detector.compilation_unit, "crytic_compile", None)
    if crytic_compile is not None:
        return id(crytic_compile)
    return id(detector.compilation_unit)


def _compilation_unit_id(compilation_unit) -> str:
    identities = []
    for contract in compilation_unit.contracts:
        canonical_name = (
            getattr(contract, "canonical_name", None)
            or getattr(contract, "name", None)
            or "<unknown-contract>"
        )
        identities.append((source_file_key(contract), str(canonical_name)))
    encoded = json.dumps(sorted(identities), separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()[:20]


def _record_json_unit(detector, unit_id, unit_stats, findings) -> None:
    if not ISD_JSON_OUT:
        return
    output_path = Path(ISD_JSON_OUT).resolve()
    run_key = (_analysis_run_token(detector), str(output_path))
    state = _JSON_RUNS.get(run_key)
    if state is None:
        state = _JsonRunState(output_path=output_path)
        _JSON_RUNS[run_key] = state
    state.units[unit_id] = {
        "unit_id": unit_id,
        "stats": dict(sorted(unit_stats.items())),
        "finding_count": len(findings),
        "findings": findings,
    }
    ordered_units = [state.units[key] for key in sorted(state.units)]
    flat_findings, unit_summaries = [], []
    for unit in ordered_units:
        unit_summaries.append({
            "unit_id": unit["unit_id"],
            "stats": unit["stats"],
            "finding_count": unit["finding_count"],
        })
        flat_findings.extend(
            {"compilation_unit_id": unit["unit_id"], **finding}
            for finding in unit["findings"]
        )
    document = {
        "schema_version": MVSCAN_JSON_SCHEMA_VERSION,
        "detector": detector_metadata(),
        "effective_config": effective_config(),
        "compilation_units": unit_summaries,
        "finding_count": len(flat_findings),
        "findings": flat_findings,
    }
    temporary_path = output_path.with_name(output_path.name + f".tmp.{os.getpid()}")
    temporary_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.replace(temporary_path, output_path)

# get block id's reads and return if the var is in its reads
def block_reads_var(bid,icfg,var) -> bool:
    reads = (icfg.blocks.get(bid, {}).get("reads", set()))
    if var in reads: return True

    if isinstance(var, MappingSlotVar):
        return var.base in reads

    members = getattr(var, "vars", None)
    if members is None: return False

    # Preferred exact relation provenance
    if (icfg.relation_reads.get(var, {}).get(bid, set())):
        return True

    member_set = set(members)
    return any(
        observed in member_set
        or (isinstance(observed,MappingSlotVar) and observed.base in member_set)
        for observed in reads
    )

def _txt(s):
    try: return str(s).replace(" ", "").lower() # normalization
    except Exception: return ""

# Does the expression have that token?
def expr_uses_any(expr, tokens) -> bool:
    if not tokens: return False
    if expr is None: return False
    return any(t in _txt(expr) for t in tokens)

# Any external/internal call in this node has args/value derived from tokens
def node_ext_arg_uses_tokens(node, tokens) -> bool:
    for ir in getattr(node, "irs", []):
        irs = _txt(ir)
        if not irs: continue
        if any(t in irs for t in tokens): return True
    return False

# Return if node writes to storage and RHS of an assignment depends on our tokens
def node_storage_write_from_tokens(node, tokens) -> bool:
    # If the node writes no storage variables or slots, skip
    writes_storage = False
    if getattr(node, "variables_written", None): writes_storage = True

    # Scan IR to detect explicit writes and RHS dependency
    for ir in getattr(node, "irs", []):
        irs = _txt(ir)
        if not irs: continue

        is_write_like = ("sstore" in irs) \
            or ("storage" in irs and (":=" in irs or "=" in irs)) \
            or ("mapping" in irs and (":=" in irs or "=" in irs))
        writes_storage = writes_storage or is_write_like

        # Does the RHS contain a tracked token
        if any(t in irs for t in tokens) and (is_write_like and writes_storage): return True
    return False

# Within the node, grow the token set via local assignments: lv := rv
def update_aliases_in_block(node, tokens):
    if not tokens: return tokens

    new_tokens = set(tokens)
    for ir in getattr(node, "irs", []):
        try:
            if isinstance(ir, Assignment):
                lv_txt, rv_txt = _txt(getattr(ir, "lvalue", None)), _txt(getattr(ir, "rvalue", None))
                if lv_txt and rv_txt and any(t in rv_txt for t in tokens):
                    new_tokens.add(lv_txt)
        except Exception:
            irs = _txt(ir)
            if "=" in irs:
                lv, rv = irs.split("=", 1)
                lv, rv = lv.strip(), rv.strip()
                if any(t in rv for t in tokens) and lv: new_tokens.add(lv)
    return new_tokens

# A new sink heuristic: a read of 'var' is notable if, along some path without overwriting 'var', its value/copies influences:
# (a) control-flow at a branch predicate
# (b) arguments/eth value to an ext/internal call
# (c) RHS of a storage write to any storage var/slot
def value_influence_hits_sensitive_sink(var, start_bid, icfg, budget) -> bool:
    if budget == 0: return False

    # Same-node sink
    if is_critical_sink_bid(start_bid, icfg) and block_reads_var(start_bid, icfg, var): return True

    seen = {start_bid}
    q = deque([start_bid])
    steps = 0
    unlimited = (budget is None)
    while q and (unlimited or steps < budget):
        cur = q.popleft()
        steps += 1
        node = node_of(cur, icfg)

        # Branch predicate uses the variable
        if node and is_branch_node(node) and block_reads_var(cur, icfg, var):
            if reachable_without_overwrite(icfg, start_bid, cur, var):
                return True

        # Any call in the block and the block reads the variable
        if node and any(isinstance(ir, (HighLevelCall, InternalCall)) for ir in getattr(node, "irs", [])):
            if block_reads_var(cur, icfg, var) and reachable_without_overwrite(icfg, start_bid, cur, var):
                return True

        # Storage write in the block and the block reads the variable
        if node and (getattr(node, "variables_written", None) or any(getattr(ir, "lvalue", None) for ir in getattr(node, "irs", []))):
            if block_reads_var(cur, icfg, var) and reachable_without_overwrite(icfg, start_bid, cur, var):
                return True

        for nxt in icfg.reachability_successors(cur):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False

# sink-test scheduler
def hits_sink(var, read_bid, icfg) -> bool:
    if SINK_TEST == "value":
        return value_influence_hits_sensitive_sink(var, read_bid, icfg, DIVERGENCE_BUDGET)
    if SINK_TEST == "samevar":
        return forward_slice_hits_sink_from(var, read_bid, icfg, DIVERGENCE_BUDGET)
    return True

### Admin/role/timelock guards

# Inline guard detection
def has_inline_admin_guard(fn) -> bool:
    for n in getattr(fn, "nodes", []):
        if n.type not in branch_types: continue

        es = _txt(getattr(n, "expression", None))
        if not es: continue

        if ("msg.sender" in es and any(tok in es for tok in ("owner", "govern", "timelock", "guardian", "multisig", "admin"))) or \
           ("hasrole" in es or "onlyrole" in es) or \
           ("msg.sender" in es and ("role" in es or "isadmin" in es or "isowner" in es)):
            return True
    return False

# Admin if it has a popular admin name or has an inline admin guard
def is_admin_only(fn) -> bool:
    return True if any(getattr(m, "name", "").lower() in {"onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlygov", "onlydao", "onlytimelock", "onlyguardian", "onlymultisig", "auth", "requiresauth", "checkowner"} for m in getattr(fn, "modifiers", []) or []) or has_inline_admin_guard(fn) else False

### Helpers for classifying nodes/shapes

# Resolve a block id to its node
def node_of(bid, icfg):
    if bid not in icfg.blocks: return None
    return icfg.node_lookup.get(bid)

def is_branch_node(node) -> bool: return (node.type in branch_types) # Check if node is a branching predicate defined by branch_types


# (DivertScan §4.2.3) Keep reads that reach external-call sites called "critical sinks." Call destination contamination could cause divergence
def is_external_call_node(node, icfg) -> bool:
    if node is None: return False # Node must exist

    # Heuristic for "critical sink": an external (cross-contract) call or dynamic low-level call
    fn = icfg.fn_lookup.get(function_key(node.function))
    if fn is None: return False
    for ir in getattr(node, "irs", []):
        if isinstance(ir, HighLevelCall):
            if ir.function is None:
                return True # dynamic or low-level call
            if getattr(ir.function, "contract_declarer", None) is not getattr(fn, "contract_declarer", None):
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
        if cur in reads_of_var and is_critical_sink_bid(cur, icfg):
            # Check for no overwrite along that part of CFG
            if reachable_without_overwrite(icfg, start_bid, cur, var): return True
        for nxt in icfg.reachability_successors(cur):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False

### Helpers for identifying init/constructor-only

def fn_entry_bid(fn):
    entry_point = getattr(fn, "entry_point", None)
    if entry_point is not None: return (function_key(fn), entry_point.node_id)

    # Pick node with no predicate or first one available
    roots = sorted((node for node in getattr(fn, "nodes", []) if not node.fathers), key=lambda node: node.node_id)
    nodes = sorted(getattr(fn, "nodes", []), key=lambda node: node.node_id)
    start = roots[0] if roots else (nodes[0] if nodes else None)
    if start is None: return None
    return (function_key(fn), start.node_id)

# Gets pre-latch tokens from `require` and `if` within the function
def latch_candidates_from_fn_guards(fn):
    toks = set()
    for n in fn.nodes:
        if n.type not in branch_types: continue
        es = _txt(getattr(n, "expression", None))
        if not es: continue

        # Bool case
        if "!" in es:
            tok = es.replace("!", "")
            if tok.isidentifier(): toks.add(tok)

        # Equality
        if "==" in es:
            left, right = es.split("==", 1)
            if left.isidentifier() and right in ("false", "0"): toks.add(left)

        # Bitmask
        if "&" in es and "==0" in es:
            left, _ = es.split("==0", 1)
            lhs = left.split("&", 1)[0]
            if lhs.isidentifier(): toks.add(lhs)

        # Versioning
        if "<" in es and "initialized" in es: toks.add("_initialized")

    # Name/modifier hint for common patterns
    nm = fn.name.lower()
    if ("init" in nm or "setup" in nm or "bootstrap" in nm) and any("initializer" in m.name.lower() or "reinitializer" in m.name.lower() for m in getattr(fn, "modifiers", [])):
        toks.add("initialized")
    return toks

# Determines if function contains a post-init guard referencing latch L in a way that implies the contract was already initialized
def fn_has_post_guard_for(fn, L) -> bool:
    for n in fn.nodes:
        if n.type not in branch_types: continue
        es = _txt(getattr(n, "expression", None))
        if not es: continue

        # Phase enums
        if L in {"initialized", "_initialized"} and ("phase==live" in es or "phase.live" in es): return True

        # Must mention the latch
        if L not in es: continue

        # Skip obvious pre-forms
        if f"!{L}" in es: continue
        if f"{L}==false" in es or f"{L}==0" in es: continue
        if L == "_initialized" and f"{L}<" in es: continue

        # Positive/post indications
        if f"{L}==true" in es or f"{L}==1" in es: return True
        if f"{L}>=" in es or f"{L}>" in es: return True
        if "&" in es and ("!=0" in es or "==0" not in es): return True

        return True
    return False

# Check if predicates are present O(1)
def preds_of(bid, icfg):
    return sorted(icfg.predecessors.get(bid, set()), key=lambda item: (str(item[0]), int(item[1])))

# We treat constructor writes as creation-phase, and check if the function is only reached from there
def is_creation_phase(v, w_bid, icfg) -> bool:
    fn = icfg.fn_lookup[w_bid[0]]
    if getattr(fn, "is_constructor", False): return True
    nm = fn.name.lower()
    if nm in {"bootstrap", "init","initialize","setup","set_up"} or any("initializer" in m.name.lower() for m in getattr(fn, "modifiers", [])):
        return True
    return False

# Accept if along any path from the write to the function return, there's an update moving L out of P_pre
def has_monotone_flip_write(L, w_bid, icfg) -> bool:
    # Over-approximate postdom region: all forward-reachable nodes in the function.
    fn, post, q = icfg.fn_lookup[w_bid[0]], set(), [w_bid]
    while q:
        cur = q.pop()
        for nxt in icfg.blocks[cur]["succ"]:
            if nxt not in post:
                post.add(nxt)
                q.append(nxt)
    
    L0 = L[0].lstrip("_").lower()
    for b in post:
        node = node_of(b, icfg)
        if node is None: continue
        for ir in getattr(node, "irs", []):
            if isinstance(ir, Assignment):
                lhs = str(getattr(ir, "lvalue", "")).lstrip("_").lower()
                rhs = str(getattr(ir, "rvalue", "")).lower()
                if lhs == L0:
                    # Monotone flips
                    if L[1] in ("bool", "eq") and ("true" in rhs or "ready" in rhs or "initialized" in rhs or "1" == rhs): return True
                    if L[1] == "mask_zero" and ("|" in rhs or "set" in rhs): return True
                    # Heuristic: Any write that looks like assignment to a non-zero/greater token
                    if L[1] == "version_lt" and (rhs not in ("0", "false")): return True
    return False

# Reject if we assign L back to a pre-init value anywhere in user-reachable code
def has_reset(L, icfg) -> bool:
    lname = L[0].lstrip("_").lower()
    for b in icfg.blocks:
        node = node_of(b, icfg)
        if node is None: continue
        for ir in getattr(node, "irs", []):
            if isinstance(ir, Assignment):
                lhs = str(getattr(ir, "lvalue", "")).lstrip("_").lower()
                rhs = str(getattr(ir, "rvalue", "")).replace(" ", "").lower()
                if lhs == lname and (rhs in ("false", "0", "phase.uninitialized") or ("&=~" in rhs)): return True
    return False

# For every public/ext entry reaching w_bid, ensure >=1 node on the path has a predicate mentioning L pre-initialization
def entry_paths_guarded(L, w_bid, icfg) -> bool:
    lname = L[0].lstrip("_").lower()

    # Walk backwards to entries
    seen, q, guarded_entries, entries = set(), [w_bid], set(), set()
    while q:
        cur = q.pop()
        fn = icfg.fn_lookup[cur[0]]
        if fn.visibility in ("public", "external"):
            entries.add(cur[0])

            # Check if one of cur's dominator(s) mentions L
            if any(lname in (str(getattr(n, "expression", "")).lower() or "") for n in fn.nodes):
                guarded_entries.add(cur[0])

        for pred in preds_of(cur, icfg):
            if pred not in seen:
                seen.add(pred)
                q.append(pred)
    return entries and entries.issubset(guarded_entries)

# Gets all L for which the func behaves like an initializer
def initializer_fn(fn, icfg):
    entry_bid = fn_entry_bid(fn)
    if entry_bid is None: return set()

    pre_latches = latch_candidates_from_fn_guards(fn)
    ok = set()
    for L in pre_latches:
        if has_monotone_flip_write((L, "eq", None), entry_bid, icfg) and not has_reset((L, "eq", None), icfg):
            ok.add(L)
    return ok

"""
(2) Accept if for every user-reachable path, find
  (a) a dominating guard that reads L and enforces it pre
  (b) a flip to move L out of pre that postdominates the write on that path,
  (c) no resets to bring L back into pre
"""
def passes_monotone_latch(v, w_bid, icfg) -> bool:
    # (a) Any predecessor chain nodes
    guard_nodes, work = {w_bid}, preds_of(w_bid, icfg)
    while work:
        b = work.pop()
        if b in guard_nodes: continue
        guard_nodes.add(b)
        work.extend(preds_of(b, icfg))

    # (b) Look for predicates of the form !x, x==c, (f & C)==0, _init < k
    latch_candidates = set()
    for n in guard_nodes:
        expr = getattr(n, "expression", None)
        if expr is None: continue
        es = str(expr).replace(" ", "").lower()

        # Bool
        if "!" in es:
            tok = es.replace("!", "")
            if tok.isidentifier(): latch_candidates.add((tok, "bool", None))
        
        # Equality and enum
        if "==" in es:
            left, right = es.split("==", 1)
            if left.isidentifier(): latch_candidates.add((left, "eq", right))
        
        # Bitmask
        if "&" in es and "==0" in es:
            left, _ = es.split("==0", 1)
            latch_candidates.add((left, "mask_zero", None))
        
        # Version
        if "<" in es and "_initialized" in es:
            latch_candidates.add(("_initialized", "version_lt", None))

    if not latch_candidates: return False

    # Check flip and no-reset for every candidate
    for L in latch_candidates:
        if has_monotone_flip_write(L, w_bid, icfg) and not has_reset(L, icfg):
            if entry_paths_guarded(L, w_bid, icfg): return True

    return False

# INIT_ONLY heuristics for filtering out any false positives that are found in initializers
def _init_only_vars(icfg) -> set:
    init_only = set()
    state_vars = [v for v in icfg.var_writes.keys() if not isinstance(v, (MappingSlotVar, MultiVarGroup, ExternalStateVar))]
    for v in state_vars:
        writes = icfg.var_writes.get(v, set())
        if not writes: continue
        if all(is_creation_phase(v, bid, icfg) or passes_monotone_latch(v, bid, icfg) for bid in writes): init_only.add(v)
    return init_only

### Variable id normalization for bucketing

def _stable_entity_name(entity) -> str:
    return str(getattr(entity, "canonical_name", None) or getattr(entity, "name", None) or entity)

# Stable id used for bucketing, shape metadata, and deduplication
def var_key(v):
    # The gid identifies the exact branch/return relation site
    if isinstance(v, MultiVarGroup):
        return ("MVG", v.semantic_id)
    if isinstance(v, MappingSlotVar):
        return ("MS", source_file_key(v.base), _stable_entity_name(v.base), str(v.key))
    if isinstance(v, ExternalStateVar):
        return ("EXT", str(v.addr), str(v.selector))
    return ("SV", source_file_key(v), _stable_entity_name(v))

# A raw detector report represents one entity/MV-relation under a transaction set
# def _finding_bucket_id(tx_id, var): return (tx_id, var_key(var))

# (DivertScan's §4.2.1) Above-tx entry normalization that merges user-selected entry names
def normalize_entry_name(entry_name) -> str:
    if entry_name in ATOMIC_GROUP:
        return "ATOMIC_GROUP"

    # Converts Contract.fn(arg,. ..) => Contract.fn
    if MERGE_OVERLOADS:
        try:
            contract, rest = entry_name.split(".", 1)
            fn = rest.split("(", 1)[0].strip().strip("'\"")
            return f"{contract}.{fn}"
        except Exception:
            return entry_name
    return entry_name

### Precise storage slot resolution (0.9.2 has no storageLayout so i built this in using related works + solidity guide)

# Builds a name: slot map for a contract from Hardhat's artifacts/build-info/*
def slot_map(contract_name: str) -> dict[str, int]:
    canon = contract_name.split(":")[-1]
    if canon in LAYOUT_CACHE: return LAYOUT_CACHE[canon]

    merged = {}
    def merge_from_build_info(path: str):
        try: data = json.loads(pathlib.Path(path).read_text())
        except Exception: return

        if not isinstance(data, dict): return

        output = data.get("output")
        if not isinstance(output, dict): return

        contracts = output.get("contracts")
        if not isinstance(contracts, dict): return
        for _, ctrs in contracts.items():
            ctr = ctrs.get(canon)
            if not isinstance(ctr, dict): continue
            layout = ctr.get("storageLayout") or {}
            for e in layout.get("storage", []) or []:
                lab, sl = (e.get("label") or "").lstrip("_"), e.get("slot")
                if lab and sl is not None:
                    try: merged.setdefault(lab, int(sl, 0))
                    except Exception: pass

    # Hardhat build-info
    for p in glob.glob("artifacts/build-info/*.json"): merge_from_build_info(p)

    # Foundry build-info
    for p in glob.glob("out/build-info/*.json"): merge_from_build_info(p)

    # Foundry per-contract artifacts (top-level storageLayout) area bit more difficult
    if not merged:
        for p in glob.glob("out/**/*.json", recursive=True):
            try: data = json.loads(pathlib.Path(p).read_text())
            except Exception: continue

            if not isinstance(data, dict): continue

            layout = data.get("storageLayout")
            if not isinstance(layout, dict): continue
            
            cn = data.get("contractName")
            if cn and cn != canon: continue
            for e in layout.get("storage", []) or []:
                lab = (e.get("label") or "").lstrip("_")
                sl  = e.get("slot")
                if lab and sl is not None:
                    try: merged.setdefault(lab, int(sl, 0))
                    except Exception: pass

    LAYOUT_CACHE[canon] = merged
    return merged

# Emit a finding to Slither's Output for later CLI use
def emit_finding(det, pattern, vars_hit, writers, readers, tx_list) -> Output:
    header = f"\n[{pattern}] " + ", ".join(vars_hit)
    lines  = [header, "  tx-set -> " + ", ".join(tx_list)]
    # Only the first few writer and reader sites are emitted, full detail in ISD_JSON_OUT
    for sig, _, f_path, l_no in writers[:2]: lines.append(f"\n • write\t{f_path}:{l_no}  ({sig})")
    for sig, _, f_path, l_no in readers[:2]: lines.append(f"\n • read\t{f_path}:{l_no}  ({sig})")
    return det.generate_result(lines) # Generate a valid result from the lines

def prettify(v): return None if getattr(v, "name", "").startswith("REF_") else getattr(v, "name", "") # Hides REF_*

"""
NOTE: NEW Added multi-variable grouping (branch groups and multi-return helpers).
Early works like DivertScan/SAILFISH were single-variable and could've used abstractions
"""
class MultiVarGroup:
    # Treat a set of related state vars as one logical variable so we can
    # 1. Detect multi-variable invariant violations
    # 2. Bucket and report them
    # 3. Propagate read and write sites into the pseudo for reachability and pair detection
    __slots__ = ("vars", "gid", "semantic_id")

    def __init__(self, gid, vars_: tuple, semantic_id: tuple):
        self.gid = gid
        self.vars = vars_
        self.semantic_id = semantic_id

    @property
    def name(self):
        return ("{" + ", ".join(sorted(filter(None, (prettify(member) for member in self.vars)))) + "}")

    # Hash the group and treat it as a statevar
    def __hash__(self): return hash(("MVG", self.semantic_id))

    # Check for equality between 2 grouping instances
    def __eq__(self, other):
        return (isinstance(other, MultiVarGroup) and self.semantic_id == other.semantic_id)

###### ADDED (2) ######

def _contract_classification_key(contract):
    if contract is None: return None
    canonical_name = (getattr(contract, "canonical_name", None) or getattr(contract, "name", None))
    if not canonical_name: return None
    return f"{source_file_key(contract)}::{canonical_name}".strip().lower()

def _concrete_state_members(var) -> set[StateVariable]:
    if isinstance(var, MappingSlotVar): return {var.base}
    if isinstance(var, MultiVarGroup):
        members=set()
        for member in var.vars: members.update(_concrete_state_members(member))
        return members
    if isinstance(var, StateVariable): return {var}
    return set()

def _contains_external_state(var) -> bool:
    if isinstance(var, ExternalStateVar): return True
    if isinstance(var, MultiVarGroup):
        return any(_contains_external_state(member) for member in var.vars)
    return False

def _requires_same_storage_context(var) -> bool:
    return not _contains_external_state(var)

def _relation_member_signature(var) -> frozenset:
    if isinstance(var, MultiVarGroup):
        return frozenset(var_key(member) for member in var.vars)
    return frozenset({var_key(var)})

def _relation_pair_tokens(var) -> set[tuple]:
    members = sorted(_relation_member_signature(var))
    return {(left, right) for left, right in combinations(members, 2)}

def _partition_relation_families(var_map):
    variables = list(var_map)
    if len(variables) <= 1:
        return [var_map]
    parent = {variable: variable for variable in variables}

    def find(variable):
        while parent[variable] != variable:
            parent[variable] = parent[parent[variable]]
            variable = parent[variable]
        return variable

    def union(left, right):
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    pair_to_relations = defaultdict(list)
    for variable in variables:
        for pair_token in _relation_pair_tokens(variable):
            pair_to_relations[pair_token].append(variable)
    for related_variables in pair_to_relations.values():
        first = related_variables[0]
        for other in related_variables[1:]:
            union(first, other)

    components = defaultdict(dict)
    for variable, records in var_map.items():
        components[find(variable)][variable] = records
    return list(components.values())

def summary_covers_relation(summary, relation) -> bool:
    for member in relation.vars:
        if not any(
            location_matches_member(written_location, member)
            for written_location in summary.must_writes
        ):
            return False
    return True

def _bucket_declaring_contracts(vars_here):
    contract_keys, unresolved = set(), []
    for var in vars_here:
        for state_var in _concrete_state_members(var):
            contract = (getattr(state_var, "contract_declarer", None) or getattr(state_var, "contract", None))
            key = _contract_classification_key(contract)
            if key is None: unresolved.append(getattr(state_var, "name", str(state_var)))
            else: contract_keys.add(key)
    if unresolved:
        raise RuntimeError("MV-Scan could not resolve declaring contracts for: " + ", ".join(sorted(set(unresolved))))
    return contract_keys

##################

# Linearized base contracts acts differently on different versions and different frameworks
def _linearized_bases(c): return ( getattr(c, "linearized_base_contracts", None) or getattr(c, "_linearizedBaseContracts", None) or [] )

# Reconstruct slot's index by linearized base's order, excludes const/immutables but works for non-constant, non-immutable statevars
def legacy_slot_fallback(v):
    # Contract declaring v
    c = (getattr(v, "contract_declarer", None) or getattr(v, "contract", None))
    if not c: return None

    ordered = [] # walk the order
    for base in reversed(_linearized_bases(c)):
        ordered.extend(sv for sv in getattr(base, "state_variables", []) if not (getattr(sv, "is_constant", False) or getattr(sv, "is_immutable", False)))
    try:
        return ordered.index(v)
    except ValueError:
        return None

# Resolve storage slot numbers for regular state vars, mapping slots, and lastly legacy fallback
def slot_of(v):
    # NOTE: Some slither versions show storage_location in compilation
    loc = getattr(v, "_storage_location", {}) or getattr(v, "storage_location", {})
    if isinstance(loc, dict) and loc.get("slot") not in (None, "UNKNOWN"): return int(loc["slot"])

    # Build-info lookup (works for new Slither versions)
    c = (getattr(v, "contract_declarer", None) or getattr(v, "contract", None))
    tbl = slot_map(c.name if c else "")
    for label in (v.name, v.name.lstrip("_")):
        if (s := tbl.get(label)) is not None: return s

    return legacy_slot_fallback(v) # NO build-info! (this usually signals a bug so further research can fix these)

### ICFG construction

def build_icfg(compilation_unit) -> ICFG:
    icfg, functions_by_key = ICFG(), {}
    def register_function_or_modifier(fn):
        key = function_key(fn)
        existing = functions_by_key.get(key)
        if existing is not None and existing is not fn:
            raise RuntimeError(f"MV-Scan encountered two distinct declared functions or modifiers with the same canonical key: {key}")
        functions_by_key[key] = fn

    for contract in compilation_unit.contracts:
        for fn in contract.functions_and_modifiers_declared:
            register_function_or_modifier(fn)
    for fn in compilation_unit.functions:
        if getattr(fn, "contract_declarer", None) is None:
            register_function_or_modifier(fn)
    functions = [functions_by_key[key] for key in sorted(functions_by_key)]
    for fn in functions:
        icfg.fn_lookup[function_key(fn)] = fn
    icfg.precompute_return_summaries(functions)

    for fn in functions:
        for node in sorted(getattr(fn, "nodes", []), key=lambda item: item.node_id):
            icfg.add_block(node)

    missing_call_sources = sorted( source for source in icfg.call_edges if source not in icfg.blocks )
    missing_call_targets = { source: sorted(target for target in targets if target not in icfg.blocks) for source, targets in icfg.call_edges.items() }
    missing_call_targets = { source: targets for source, targets in missing_call_targets.items() if targets }
    if missing_call_sources or missing_call_targets:
        raise RuntimeError(f"MV-Scan completed ICFG construction with invalid call edges: missing_sources={missing_call_sources}, missing_targets={missing_call_targets}")
    
    icfg.rebuild_predecessors()
    return icfg

### (DivertScan) §4.2.1 Entry reachability and user-callable heuristics

# How a function is considered user-callable.
#
# contextual_ids supports a first-party owner identity for inherited functions.
# Existing USER_CALLABLE_ALWAYS / USER_CALLABLE_DENY behavior remains compatible with canonical function keys and legacy fullnames
def is_user_callable(fn, contextual_ids=()) -> bool:
    # Public or external and not a constructor or initializer.
    if (fn.visibility not in ("public", "external") or fn.is_constructor or fn.name.startswith("initialize")):
        return False

    # Treat common init-like names as non-user-callable
    name = fn.name.lower()
    if (name in {"init", "initialize", "setup", "set_up", "bootstrap"} or name.startswith("initialize")):
        return False

    candidate_ids = { function_key(fn), getattr(fn, "full_name", ""), *contextual_ids }
    candidate_ids.discard("")

    # Deny wins over force-include
    if candidate_ids & USER_CALLABLE_DENY: return False
    if candidate_ids & USER_CALLABLE_ALWAYS: return True
    if (not USER_CALLABLE_INCLUDE_ROLE_GATED and is_admin_only(fn)): return False
    return True

def _normalized_source_path(obj) -> str:
    raw_path = str(source_file_key(obj))
    normalized = raw_path.replace("\\", "/").strip().lower()
    return "/" + normalized.lstrip("/")

def _source_is_dependency(obj) -> bool:
    source_mapping = getattr(obj, "source_mapping", None)
    if bool(getattr(source_mapping, "is_dependency", False)): return True
    return "/node_modules/" in _normalized_source_path(obj)

def _bool_attr(obj, attribute_name: str) -> bool:
    value = getattr(obj, attribute_name, False)
    
    # Slither/framework version may expose as method
    if callable(value):
        try: value = value()
        except TypeError: return False
    return bool(value)

# Give a reason for excluding a root
def _root_contract_exclusion_reason(contract):
    if _source_is_dependency(contract): return "dependency"

    source_path = _normalized_source_path(contract)
    if any(marker in source_path for marker in _ROOT_TEST_PATH_MARKERS): return "test_or_mock"

    # Code providers
    if _bool_attr(contract, "is_interface"): return "interface"
    if _bool_attr(contract, "is_library"): return "library"
    if _bool_attr(contract, "is_abstract"): return "abstract"
    return None

# Identify the externally callable deployment context
def _root_owner_key(contract, fn) -> str:
    contract_name = (getattr(contract, "canonical_name", None) or getattr(contract, "name", None) or "<unknown-contract>")
    return f"{source_file_key(contract)}::{contract_name}.{fn.full_name}"

# Maps every user-reachable block to every externally relevant analysis owner
# * ICFG identifies physical implementation blocks
# * It does not clone those per deployed derived contract.
# * So each physical entry_bid must receive exactly one owner.
def compute_entry_owners(icfg: ICFG, compilation_unit):
    entry_owners, worklist, stats = defaultdict(set), deque(), defaultdict(int)
    entry_contexts = defaultdict(set)
    root_candidates: dict[BasicBlock, dict[str, dict]] = defaultdict(dict)

    icfg.entry_contexts_by_block.clear()
    icfg.root_function_by_owner.clear()
    icfg.root_owner_by_entry.clear()
    icfg.root_exposures.clear()

    contracts = sorted(
        getattr(compilation_unit, "contracts", []) or [],
        key=lambda contract: (
            _normalized_source_path(contract),
            str(getattr(contract, "canonical_name", None) or getattr(contract, "name", "")),
        ),
    )

    # Phase 1: collect every eligible concrete exposure without seeding yet
    for contract in contracts:
        exclusion_reason = _root_contract_exclusion_reason(contract)
        entry_functions = list(getattr(contract, "functions_entry_points", None) or getattr(contract, "functions", []) or [])
        entry_functions.sort(key=lambda fn: (getattr(fn, "full_name", ""), function_key(fn)))

        for fn in entry_functions:
            raw_exposure_owner = _root_owner_key(contract, fn)
            raw_implementation_owner = function_key(fn)

            exposure_owner = normalize_entry_name(raw_exposure_owner)
            implementation_owner = normalize_entry_name(raw_implementation_owner)
            force_ids = {
                raw_exposure_owner,
                raw_implementation_owner,
                getattr(fn, "full_name", ""),
                exposure_owner,
                implementation_owner,
            }
            force_ids.discard("")

            force_included = bool(force_ids & USER_CALLABLE_ALWAYS)

            if not is_user_callable(fn, contextual_ids=(raw_exposure_owner, exposure_owner)):
                stats["rejected_non_callable"] += 1
                continue

            # Explicit USER_CALLABLE_ALWAYS may restore an otherwise excluded dependency/test context.
            if (exclusion_reason is not None and not force_included):
                stats[f"excluded_{exclusion_reason}"] += 1
                continue

            entry_bid = fn_entry_bid(fn)
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
                "implementation_is_dependency": (
                    _source_is_dependency(fn)
                ),
                "storage_context": _contract_classification_key(contract),
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
        candidates = sorted(
            root_candidates[entry_bid].values(),
            key=candidate_sort_key,
        )
        chosen = candidates[0]
        exposures = { candidate["exposure_owner"] for candidate in candidates }

        # Explicit force-inclusion should retain the explicitly selected id
        if chosen["force_included"]:
            analysis_owner = chosen["exposure_owner"]

        # One stable first-party concrete exposure
        elif chosen["implementation_is_dependency"]:
            analysis_owner = chosen["exposure_owner"]

        # For first-party inherited implementations, use the physical implementation id
        else:
            analysis_owner = chosen["implementation_owner"]

        icfg.root_owner_by_entry[entry_bid] = analysis_owner
        icfg.root_exposures[analysis_owner].update(exposures)

        if len(exposures) > 1:
            stats["multi_exposure_entry_blocks"] += 1

        stats["collapsed_contextual_aliases"] += (len(candidates) - 1)
        root_function = chosen["root_function"]
        previous_root_function = icfg.root_function_by_owner.get(analysis_owner)
        if previous_root_function is not None and previous_root_function is not root_function:
            raise RuntimeError(
                "One analysis owner resolved to multiple root functions: "
                f"{analysis_owner}"
            )
        icfg.root_function_by_owner[analysis_owner] = root_function

        storage_contexts = {
            candidate["storage_context"]
            for candidate in candidates
        }
        for storage_context in sorted(storage_contexts):
            worklist.append((entry_bid, analysis_owner, storage_context))
        stats["seeded_contexts"] += len(storage_contexts)
        stats["seeded"] += 1

    # Phase 3: propagate the selected analysis owners and storage domains.
    while worklist:
        block_id, owner, storage_context = worklist.popleft()
        if block_id not in icfg.blocks: continue
        execution_context = (owner, storage_context)
        if execution_context in entry_contexts[block_id]: continue

        entry_contexts[block_id].add(execution_context)
        for successor in sorted(
            icfg.cfg_successors(block_id),
            key=lambda bid: (str(bid[0]), int(bid[1])),
        ):
            if successor in icfg.blocks:
                worklist.append((successor, owner, storage_context))

        for successor in sorted(
            icfg.call_successors(block_id),
            key=lambda bid: (str(bid[0]), int(bid[1])),
        ):
            if successor not in icfg.blocks: continue
            edge_key = (block_id, successor)
            edge_mode = icfg.call_edge_context_modes.get(edge_key)
            if edge_mode is None:
                raise RuntimeError(f"Call edge has no storage-context mode: {edge_key}")
            mode, target_context = edge_mode
            if mode == "preserve":
                next_storage_context = storage_context
            elif mode == "switch":
                next_storage_context = target_context or "<unknown-storage-context>"
            else:
                raise RuntimeError(f"Unknown call-edge context mode: {mode}")
            worklist.append((successor, owner, next_storage_context))

    print(
        "[mvscan-stage] root-seeding-done "
        f"eligible_exposures="
        f"{stats['eligible_exposures']} "
        f"seeded={stats['seeded']} "
        f"multi_exposure_entry_blocks="
        f"{stats['multi_exposure_entry_blocks']} "
        f"collapsed_contextual_aliases="
        f"{stats['collapsed_contextual_aliases']} "
        f"excluded_dependency="
        f"{stats['excluded_dependency']} "
        f"excluded_test_or_mock="
        f"{stats['excluded_test_or_mock']} "
        f"excluded_interface="
        f"{stats['excluded_interface']} "
        f"excluded_library="
        f"{stats['excluded_library']} "
        f"excluded_abstract="
        f"{stats['excluded_abstract']} "
        f"missing_entry_point="
        f"{stats['missing_entry_point']} "
        f"missing_entry_block="
        f"{stats['missing_entry_block']}",
        file=sys.stderr,
        flush=True,
    )

    icfg.entry_contexts_by_block.update({
        block_id: set(contexts)
        for block_id, contexts in entry_contexts.items()
    })
    return {
        block_id: {owner for owner, _ in contexts}
        for block_id, contexts in entry_contexts.items()
    }

# Intersect each variable: blocks set with the reachable blocks and drop any empties
# Keeps read/write maps consistent after pruning for reachability
def filter_bid_map(bid_map: dict[StateVariable, set[BasicBlock]], keep):
    for v in list(bid_map.keys()):
        bid_map[v].intersection_update(keep)
        if not bid_map[v]: del bid_map[v]

def filter_relation_access_map(relation_map, keep):
    for relation in list(relation_map.keys()):
        accesses_by_block = (relation_map[relation])

        for block_id in list(accesses_by_block.keys()):
            if block_id not in keep:
                del accesses_by_block[block_id]

        if not accesses_by_block:
            del relation_map[relation]

# Helper to return (filename, first_line) for a (fn_name, node_id) block id
def src(bid, icfg):
    fn = icfg.fn_lookup[bid[0]]
    if fn is None: return "<unknown>", 0

    node = next((n for n in fn.nodes if n.node_id == bid[1]), None)
    if node is None or getattr(node, "source_mapping", None) is None: return "<unknown>", 0
    return node.source_mapping.filename.short, min(node.source_mapping.lines)

def fn_id(fn):
    # Return a uuid for a Slither func
    try: contract = fn.contract_declarer.name
    except AttributeError: contract = "<unknown>"
    raw_sig = getattr(fn, "signature", None)
    if not raw_sig:
        raw_sig = f"{fn.name}(" + ",".join(str(p.type) for p in fn.parameters) + ")"
    elif not isinstance(raw_sig, str):
        raw_sig = str(raw_sig)
    # recompute if needed
    pretty = f"{contract}.{raw_sig}"
    sel = getattr(fn, "selector", None)
    if sel is None: sel = int.from_bytes(keccak(text=raw_sig)[:4], "big")
    return pretty, hex(sel)

# Convert to u256 if you can, drop if can't
def _u256_or_none(s):
    try: return int(s, 0)
    except Exception:
        if isinstance(s, str) and s.startswith("0x"):
            try: return int(s, 16)
            except Exception: pass
    return None


def _jsonable(value):
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, (frozenset, set)):
        return sorted((_jsonable(item) for item in value), key=str)
    return value

"""
Pack variable metadata for JSON
• kind: state | external | mapping_slot | multi_var_group
• slot/base_slot/key where applicable
• branch_groups that mention the variable, useful for context
"""
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
                for member in sorted(
                    icfg.relation_shadowed_members.get(v, set()), key=var_key
                )
            ],
            "unresolved_base_read_count": sum(
                len(accesses)
                for accesses in icfg.relation_unresolved_base_reads
                .get(v, {}).values()
            ),
            "unresolved_base_write_count": sum(
                len(accesses)
                for accesses in icfg.relation_unresolved_base_writes
                .get(v, {}).values()
            ),
        }

    meta = {"name": vname_prettified, "entity_key": _jsonable(var_key(v))}
    if isinstance(v, ExternalStateVar):
        meta["kind"] = "external"
    elif isinstance(v, MappingSlotVar):
        base = slot_of(v.base)
        meta.update({"kind": "mapping_slot", "base_slot": base, "key": v.key})
        k = _u256_or_none(v.key)
        if k is not None and base is not None:
            meta["slot"] = int.from_bytes(keccak(encode(["uint256","uint256"], [k, base])), "big")
        else: meta["slot_expr"] = v.key
    else:
        meta.update({"kind": "state", "slot": slot_of(v)})

    # Attach any branch-group id(s) that references this variable/base-mapping
    bg = icfg.var_to_branchgroups.get(v, set())
    if isinstance(v, MappingSlotVar): bg |= icfg.var_to_branchgroups.get(v.base, set())
    if bg: meta["branch_groups"] = sorted(bg)

    return meta


def witness_sort_key(record: FindingWitnessRecord) -> tuple:
    return (
        record.writer_owner, record.writer_storage_context,
        str(record.writer_bid[0]), int(record.writer_bid[1]),
        record.reader_owner, record.reader_storage_context,
        str(record.reader_bid[0]), int(record.reader_bid[1]),
        record.operation_pattern, record.writer_file, record.writer_line,
        record.reader_file, record.reader_line,
    )


def _serialize_witness(record, subject_index, icfg):
    writer_sig, writer_selector = fn_id(icfg.fn_lookup[record.writer_bid[0]])
    reader_sig, reader_selector = fn_id(icfg.fn_lookup[record.reader_bid[0]])
    return {
        "subject_index": subject_index,
        "operation_pattern": record.operation_pattern,
        "writer": {
            "context": {
                "owner": record.writer_owner,
                "storage_context": record.writer_storage_context,
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
                "writer_match_kind": evidence.writer_match_kind,
                "reader_match_kind": evidence.reader_match_kind,
            }
            for evidence in record.relation_evidence
        ],
    }

### Inconsistent state detector

class InconsistentState(AbstractDetector):
    """ Detect the inconsistent states """

    # Slither will launch the detector with slither . --detect inconsistent_state
    ARGUMENT = 'inconsistent_state'
    HELP = 'Inconsistent state detector'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = '..'
    WIKI_TITLE = 'Inconsistent state detector'
    WIKI_DESCRIPTION = 'Plugin testing'
    WIKI_EXPLOIT_SCENARIO = '..'
    WIKI_RECOMMENDATION = '..'

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
        (8) Detect any "shapes" of the finding (reentrancy, shared-callee)
        (9) Bucket by transaction set and variable
        (10)Canonicalize and deduplicate findings.
        (11)Emit Slither Output and machine-readable JSON for the exploit generator.
    """
    def _detect(self) -> List[Output]:
        if MVSCAN_STRICT_CONFIG:
            reject_unknown_prefixed_environment(
                "MVSCAN_", _KNOWN_MVSCAN_ENV
            )
        print(
            "[mvscan-config] " + json.dumps(effective_config(), sort_keys=True),
            file=sys.stderr,
            flush=True,
        )
        LAYOUT_CACHE.clear()
        reset_icfg_analysis_caches()
        unit_id = _compilation_unit_id(self.compilation_unit)

        # Storage layout checks
        for c in self.compilation_unit.contracts_derived:
            if hasattr(c, "set_storage_layout"): c.set_storage_layout()
            elif hasattr(c, "compute_storage_layout"): c.compute_storage_layout()

        # Deduplication key set across the findings
        seen: set[tuple] = set()

        # Set of all JSON-encoded findings and results
        json_findings, results = [], []
        pair_stats = defaultdict(int)

        # Builds the ICFG
        icfg = build_icfg(self.compilation_unit)
        print(f"[mvscan-stage] icfg-built blocks={len(icfg.blocks)} variables={len(icfg.var_writes)}", file=sys.stderr, flush=True)

        # Identify all admin-only functions
        global ADMIN_ONLY
        ADMIN_ONLY = { function_key(f) for f in icfg.fn_lookup.values() if is_admin_only(f) }

        # Compute initialization-only variables before prune step
        pre_prune_init_only = set()
        init_latches_by_outer = defaultdict(set)
        all_init_latches: set[str] = set()
        if INIT_ONLY_FILTER:
            print("[mvscan-stage] init-filter-start", file=sys.stderr, flush=True)
            pre_prune_init_only = _init_only_vars(icfg)
            print(f"[mvscan-stage] init-filter-done vars={len(pre_prune_init_only)}", file=sys.stderr, flush=True)
        if INIT_ONLY_FILTER:
            for fn in icfg.fn_lookup.values():
                if fn.visibility not in ("public", "external"): continue
                outer = normalize_entry_name(function_key(fn))
                Ls = initializer_fn(fn, icfg)
                if Ls:
                    init_latches_by_outer[outer].update(Ls)
                    all_init_latches |= Ls
        post_guarded_by_latch = defaultdict(set)
        if INIT_ONLY_FILTER and all_init_latches:
            for fn in icfg.fn_lookup.values():
                if fn.visibility not in ("public", "external"): continue
                outer = normalize_entry_name(function_key(fn))
                for L in all_init_latches:
                    if fn_has_post_guard_for(fn, L): post_guarded_by_latch[L].add(outer)
        
        bg_pseudos, pseudo_by_semantic_id = {}, {}

        def normalize_relation_members(raw_members):
            eligible_members = set()
            for member in raw_members:
                pair_stats["relation_members_raw"] += 1
                if not relation_member_is_eligible(member):
                    pair_stats["relation_members_ineligible_filtered"] += 1
                    continue
                concrete_base = relation_member_base(member)
                if INIT_ONLY_FILTER and concrete_base in pre_prune_init_only:
                    pair_stats["relation_members_init_filtered"] += 1
                    continue
                eligible_members.add(member)
            exact_mapping_bases = {
                member.base for member in eligible_members
                if isinstance(member, MappingSlotVar)
            }
            shadowed_base_members = {
                member for member in eligible_members
                if isinstance(member, StateVariable)
                and member in exact_mapping_bases
            }
            return eligible_members - shadowed_base_members, shadowed_base_members

        # Register one MV relation
        def register_pseudo(gid, raw_members):
            # Slither may expose empty control-sink summaries inconsistently;
            # they are not relation origins and carry no members to account.
            if not raw_members:
                return None
            pair_stats["relation_origins_seen"] += 1
            logical_members, shadowed_base_members = normalize_relation_members(
                raw_members
            )
            pair_stats["relation_base_members_shadowed"] += len(
                shadowed_base_members
            )
            if len(logical_members) < 2:
                pair_stats["relation_origins_rejected_unary_after_shadowing"] += 1
                return None
            members = tuple(sorted(logical_members, key=var_key))
            semantic_id = tuple(var_key(member) for member in members)

            pseudo = pseudo_by_semantic_id.get(semantic_id)
            if pseudo is None:
                pseudo = MultiVarGroup(gid=gid, vars_=members, semantic_id=semantic_id)
                pseudo_by_semantic_id[semantic_id] = pseudo
                pair_stats["relation_origins_registered"] += 1
            else:
                pair_stats["relation_origins_merged_existing"] += 1

            bg_pseudos[gid] = pseudo
            icfg.relation_origins[pseudo].add(gid)
            icfg.relation_shadowed_members[pseudo].update(shadowed_base_members)

            def register_relation_access(
                entity, block_ids, relation_access_map, unresolved_access_map,
                aggregate_map,
            ):
                if isinstance(entity, MultiVarGroup):
                    return
                matched_members = matching_relation_members(members, entity)
                if matched_members:
                    aggregate_map[pseudo].update(block_ids)
                    for block_id in block_ids:
                        relation_access_map[pseudo][block_id].add(entity)
                    return
                if entity in shadowed_base_members:
                    for block_id in block_ids:
                        unresolved_access_map[pseudo][block_id].add(entity)

            # Register only currently existing concrete accesses
            concrete_reads, concrete_writes = list(icfg.var_reads.items()), list(icfg.var_writes.items())
            for entity, block_ids in concrete_reads:
                register_relation_access(
                    entity, block_ids, icfg.relation_reads,
                    icfg.relation_unresolved_base_reads, icfg.var_reads,
                )

            for entity, block_ids in concrete_writes:
                register_relation_access(
                    entity, block_ids, icfg.relation_writes,
                    icfg.relation_unresolved_base_writes, icfg.var_writes,
                )

            return pseudo
        
        # - Include BOTH mapping slots and their base mapping in the group, so co-use like
        #   balances[user] together with balances (base) doesn't get collapsed.
        # - Full MV-Scan unions reads/writes from BOTH the slot and the base into the pseudo.
        if ENABLE_MULTI_RETURN_GROUPS:
            for fn, ret_vars in (icfg.fn_returns.items()):
                members = {
                    returned_location
                    for returned_location in ret_vars
                    if relation_member_is_eligible(returned_location)
                }
                register_pseudo(f"return::{function_key(fn)}", members)

        # # Flag to show the pseudovariables in order to better understand grouping structure
        # if os.getenv("DEBUG_PSEUDOVARS"):
        #     for pseudo in bg_pseudos.values(): print("[bg] pseudo", pseudo.gid, "->", pseudo.name)

        # Build call-graph edges
        call_edges_intra: dict[str, set[str]] = defaultdict(set) # NOTE: Currently unused, but left for future work
        call_edges_any: dict[str, set[str]] = defaultdict(set)
        for fn in icfg.fn_lookup.values():
            for n in fn.nodes:
                for ir in getattr(n, "irs", []):
                    if not isinstance(ir, (HighLevelCall, InternalCall)): continue
                    callee = ir.function
                    if callee is None: continue  # Ignore dynamic/low-level calls
                    caller_ctr, callee_ctr = getattr(fn, "contract_declarer", None), getattr(callee, "contract_declarer", None)
                    caller_id, callee_id = function_key(fn), function_key(callee)
                    call_edges_any[caller_id].add(callee_id)
                    if caller_ctr is callee_ctr: call_edges_intra[caller_id].add(callee_id)

        # (DivertScan §4.2.1) Restrict analysis to blocks transitively reachable from real user-callable entry blocks.
        # A block may be reachable from multiple external roots.
        entry_owners = compute_entry_owners(icfg, self.compilation_unit)
        keep: set[BasicBlock] = set(entry_owners)
        print(f"[mvscan-stage] reachability-done blocks={len(keep)} owner-relations={sum(len(owners) for owners in entry_owners.values())}", file=sys.stderr, flush=True)

        # Prune unreachable blocks and synchronize read/write maps
        icfg.blocks = {b: info for b, info in icfg.blocks.items() if b in keep}
        icfg.rebuild_predecessors()
        filter_bid_map(icfg.var_reads, keep)
        filter_bid_map(icfg.var_writes, keep)
        filter_relation_access_map(icfg.relation_reads,keep)
        filter_relation_access_map(icfg.relation_writes,keep)
        filter_relation_access_map(icfg.relation_unresolved_base_reads, keep)
        filter_relation_access_map(icfg.relation_unresolved_base_writes, keep)

        print("[mvscan-stage] sensitive-read-analysis-start", file=sys.stderr, flush=True)
        icfg.compute_sensitive_read_events(keep)
        print(f"[mvscan-stage] sensitive-read-analysis-done events={len(icfg.sensitive_read_events)}", file=sys.stderr, flush=True)

        if ENABLE_BRANCH_GROUPS:
            for sink_site, read_events in icfg.sink_reads_by_site.items():
                if sink_site.kind != "control":
                    continue
                members = {
                    event.location
                    for event in read_events
                    if relation_member_is_eligible(event.location)
                }
                register_pseudo(
                    (
                        f"sink::{sink_site.block_id[0]}::"
                        f"{sink_site.block_id[1]}::{sink_site.ir_index}"
                    ),
                    members,
                )

        icfg.compute_function_write_summaries(keep)

        # Bucket findings by tx-set: var: pairs with shape tags
        buckets = defaultdict(lambda: defaultdict(list)) # {tx_id: {var: [(w_bid,r_bid,pattern,srcs...)]}}
        shapes_by_key = defaultdict(lambda: {"shared_callee": False, "reentrant": False})
        print("[mvscan-stage] pair-enumeration-start", file=sys.stderr, flush=True)

        sink_cache = {}
        def reader_passes_sink(var, reader_bid):
            cache_key = (var, reader_bid)
            if cache_key not in sink_cache:
                sink_cache[cache_key] = hits_sink(var, reader_bid, icfg)
            return sink_cache[cache_key]

        for witness in stale_read_pairs(
            icfg,
            reader_filter=reader_passes_sink,
            pair_stats=pair_stats,
        ):
            w_bid = witness.writer_bid
            r_bid = witness.reader_bid
            var = witness.variable
            base_pattern = witness.operation_pattern
            """
            (DivertScan §4.2.1) (transaction-level) Enumerates all pairs of public entries by bucketing on tx_id.
            (DivertScan §4.2.2) Pairs are implicitly public-only due to reachability pruning.
            """

            # Preserve the existing admin-write filtering behavior
            if ADMIN_WRITES_BENIGN:
                w_full, r_full = w_bid[0], r_bid[0]
                if w_full in ADMIN_ONLY and r_full not in ADMIN_ONLY:
                    pair_stats["admin_filtered"] += 1
                    continue

            # Skip variables proven to be initialization-only
            if INIT_ONLY_FILTER:
                if isinstance(var, MultiVarGroup):
                    if any(relation_member_base(member) in pre_prune_init_only for member in var.vars):
                        pair_stats["init_variable_filtered"] += 1
                        continue

                else:
                    concrete_var = relation_member_base(var)
                    if (concrete_var in pre_prune_init_only):
                        pair_stats["init_variable_filtered"] += 1
                        continue

            # Internal block may be reachable from multiple public/external entrypoints
            write_contexts = icfg.entry_contexts_by_block.get(w_bid, set())
            read_contexts = icfg.entry_contexts_by_block.get(r_bid, set())
            if not write_contexts or not read_contexts:
                raise RuntimeError(
                    "MV-Scan found a retained access without an execution context: "
                    f"write={w_bid}, read={r_bid}, var={var}"
                )

            # Information that depends only on the concrete blocks is computed once.
            w_full, r_full = w_bid[0], r_bid[0]
            w_file, w_line = src(w_bid, icfg)
            r_file, r_line = src(r_bid, icfg)

            w_callees = call_edges_any.get(w_full, set())
            r_callees = call_edges_any.get(r_full, set())

            shared_callee = bool(w_callees and r_callees and (w_callees & r_callees))

            # Evaluate every externally reachable tx context for the w/r pair
            for outer_w, storage_w in sorted(write_contexts):
                for outer_r, storage_r in sorted(read_contexts):
                    pair_stats["owner_context_pairs_considered"] += 1
                    if (
                        MVSCAN_REQUIRE_DISTINCT_OUTER_ROOTS
                        and outer_w == outer_r
                    ):
                        pair_stats["same_outer_root_filtered"] += 1
                        continue
                    if _requires_same_storage_context(var) and storage_w != storage_r:
                        pair_stats["storage_context_mismatch"] += 1
                        continue
                    pattern = base_pattern

                    # If outer entries don't match, it is a cross-transaction pattern
                    if pattern == "stale_read" and outer_w != outer_r:
                        pattern = "cross_tx_stale_read"

                    if INIT_ONLY_FILTER:
                        init_latches = init_latches_by_outer.get(outer_w, set())
                        post_guarded = any(outer_r in post_guarded_by_latch.get(latch, set()) for latch in init_latches)
                        if post_guarded:
                            pair_stats["init_context_filtered"] += 1
                            continue

                    if isinstance(var, MultiVarGroup):
                        writer_root_fn = icfg.root_function_by_owner.get(outer_w)
                        writer_summary = icfg.function_write_summaries.get(writer_root_fn)
                        if (
                            writer_summary is not None
                            and summary_covers_relation(writer_summary, var)
                        ):
                            pair_stats["must_full_relation_filtered"] += 1
                            continue

                    pair_stats["owner_context_pairs"] += 1
                    tx_id = frozenset({
                        (outer_w, storage_w),
                        (outer_r, storage_r),
                    })

                    # Reentrancy heuristic labels
                    reentrant = False
                    if outer_w != outer_r:
                        directly_linked = (r_full in call_edges_any.get(w_full, set()) or w_full in call_edges_any.get(r_full, set()))
                        if directly_linked:
                            reentrant = True
                            if pattern in {"stale_read", "cross_tx_stale_read"}:
                                pattern = "reentrant_stale_read"
                            elif pattern == "destructive_write":
                                pattern = "reentrant_destructive_write"

                    if shared_callee:
                        shapes_by_key[(tx_id, var_key(var))]["shared_callee"] = True
                    if reentrant:
                        shapes_by_key[(tx_id, var_key(var))]["reentrant"] = True

                    pair_record = FindingWitnessRecord(
                        subject=var,
                        writer_bid=w_bid,
                        reader_bid=r_bid,
                        writer_owner=outer_w,
                        writer_storage_context=storage_w,
                        reader_owner=outer_r,
                        reader_storage_context=storage_r,
                        operation_pattern=pattern,
                        writer_file=w_file,
                        writer_line=w_line,
                        reader_file=r_file,
                        reader_line=r_line,
                        relation_evidence=witness.relation_evidence,
                    )

                    # One raw finding per entity/relation and transaction set
                    # bucket_id = _finding_bucket_id(tx_id, var)
                    # buckets[bucket_id][var].append(pair_record)
                    if ENABLE_MULTIVAR_GROUPS:
                        # all subjects sharing a transaction set enter
                        bucket_id = tx_id
                    else:
                        # SV-only retains one bucket per entity
                        bucket_id = (tx_id, var_key(var))
                    buckets[bucket_id][var].append(pair_record)

        # Emit canonicalized buckets to Slither Output/JSON
        def emit_var_map(tx_id, var_map):
            # Classify bucket type
            vars_here = sorted(var_map.keys(), key=lambda var: (getattr(var, "name", str(var)), type(var).__name__))
            declaring_contracts = _bucket_declaring_contracts(vars_here)
            contains_external_state = any(_contains_external_state(var) for var in vars_here)

            # (1) Standard single-variable inconsistent state finding
            # (2) Multiple variables declared in same contract
            # (3) Multiple variables declared in different contracts
            if len(vars_here) == 1 and not isinstance(vars_here[0], MultiVarGroup):
                bucket_class = "single_var_cross_tx"
            elif contains_external_state:
                # Preserve external-state classification until validated
                bucket_class = "multi_var_cross_contract"
            elif len(declaring_contracts) == 1:
                bucket_class = "multi_var_intra_contract"
            elif len(declaring_contracts) >= 2:
                bucket_class = "multi_var_cross_contract"
            else:
                raise RuntimeError("MV-Scan encountered an MV bucket with no resolvable StateVariable contract ownership: " + ", ".join(
                    sorted(getattr(var, "name", str(var)) for var in vars_here))
                )

            tx_contexts = sorted(tx_id)
            tx_list = sorted({owner for owner, _ in tx_contexts})
            storage_contexts = sorted({
                storage_context
                for _, storage_context in tx_contexts
            })

            # Collect a few example sites/op-level patterns for the bucket
            writers, readers, op_patterns = [], [], set()
            complete_records = []
            for v, pairs in var_map.items():
                for record in pairs[:3]:
                    w_sig, w_sel = fn_id(icfg.fn_lookup[record.writer_bid[0]])
                    r_sig, r_sel = fn_id(icfg.fn_lookup[record.reader_bid[0]])
                    writers.append(
                        (w_sig, w_sel, record.writer_file, record.writer_line)
                    )
                    readers.append(
                        (r_sig, r_sel, record.reader_file, record.reader_line)
                    )
                    op_patterns.add(record.operation_pattern)
                complete_records.extend(pairs)

            # Aggregate shape tags across variables
            agg_shape = {
                "shared_callee": any(shapes_by_key[(tx_id, var_key(v))]["shared_callee"] for v in vars_here),
                "reentrant": any(shapes_by_key[(tx_id, var_key(v))]["reentrant"] for v in vars_here),
            }
            per_var_shapes = [{ "var": var_meta(v, icfg), "shape": shapes_by_key[(tx_id, var_key(v))] } for v in vars_here]

            """
            We canonicalize and deduplicate the pattern, variables, transaction set, writers, and readers.
            This ensures a stable JSON output.
            """
            writers, readers = sorted(set(writers)), sorted(set(readers))
            dedup_vars = [ var_key(v) for v in vars_here ]

            if COARSE_DEDUP:
                key = (
                    bucket_class,
                    tuple(sorted(dedup_vars)),  # shape, not site
                    tuple(tx_contexts),
                    tuple(sorted(op_patterns)),
                    agg_shape["reentrant"],
                    agg_shape["shared_callee"]
                )
            else:
                key = (
                    bucket_class,
                    tuple(sorted([v.name for v in vars_here])),
                    tuple(tx_contexts),
                    frozenset(writers),
                    frozenset(readers),
                )
            if key in seen:
                pair_stats["dedup_filtered"] += 1
                return
            seen.add(key)
            pair_stats["relation_families_emitted"] += 1
            pair_stats["findings_emitted"] += 1

            subject_indexes = {
                subject: index for index, subject in enumerate(vars_here)
            }
            complete_records = sorted(complete_records, key=witness_sort_key)
            complete_witnesses = [
                _serialize_witness(
                    record, subject_indexes[record.subject], icfg
                )
                for record in complete_records
            ]
            all_operation_patterns = {
                record.operation_pattern for record in complete_records
            }

            # JSON finding
            json_findings.append({
                "pattern": bucket_class,
                "vars": [var_meta(v, icfg) for v in vars_here],
                "tx_set": tx_list,
                "tx_contexts": [
                    {
                        "owner": owner,
                        "storage_context": storage_context,
                    }
                    for owner, storage_context in tx_contexts
                ],
                "writer_examples": [{"sig": sig, "selector": sel, "file": f, "line": l} for sig, sel, f, l in writers],
                "reader_examples": [{"sig": sig, "selector": sel, "file": f, "line": l} for sig, sel, f, l in readers],
                "op_patterns": sorted(all_operation_patterns),
                "witness_count": len(complete_witnesses),
                "witnesses": complete_witnesses,
                "shape": agg_shape, # aggregated across variables
                "shape_by_var": per_var_shapes, # precise per variable
            })

            # Slither Output objs
            results.append(emit_finding(self, bucket_class, [v.name for v in vars_here], writers, readers, tx_list))

        for bucket_id, full_var_map in buckets.items():
            tx_id = bucket_id if ENABLE_MULTIVAR_GROUPS else bucket_id[0]
            family_maps = (
                _partition_relation_families(full_var_map)
                if ENABLE_MULTIVAR_GROUPS
                else [full_var_map]
            )
            for var_map in family_maps:
                pair_stats["relation_families_considered"] += 1
                emit_var_map(tx_id, var_map)

        for key in (
            "variables_considered",
            "scalar_variables_skipped",
            "eligible_writers",
            "eligible_readers",
            "raw_block_pairs",
            "relation_incompatible",
            "storage_context_mismatch",
            "admin_filtered",
            "init_filtered",
            "must_full_relation_filtered",
            "owner_context_pairs",
            "relation_families_emitted",
        ):
            pair_stats[key] += 0
        pair_stats["init_filtered"] = (
            pair_stats["init_variable_filtered"]
            + pair_stats["init_context_filtered"]
        )
        pair_stats["relation_unresolved_base_reads"] = sum(
            len(accesses)
            for by_block in icfg.relation_unresolved_base_reads.values()
            for accesses in by_block.values()
        )
        pair_stats["relation_unresolved_base_writes"] = sum(
            len(accesses)
            for by_block in icfg.relation_unresolved_base_writes.values()
            for accesses in by_block.values()
        )
        accounted_contexts = (
            pair_stats["same_outer_root_filtered"]
            + pair_stats["storage_context_mismatch"]
            + pair_stats["init_context_filtered"]
            + pair_stats["must_full_relation_filtered"]
            + pair_stats["owner_context_pairs"]
        )
        if accounted_contexts != pair_stats["owner_context_pairs_considered"]:
            raise RuntimeError(
                "MV-Scan owner-context accounting mismatch: "
                f"considered={pair_stats['owner_context_pairs_considered']} "
                f"accounted={accounted_contexts}"
            )
        if (
            pair_stats["relation_families_considered"]
            != pair_stats["dedup_filtered"] + pair_stats["findings_emitted"]
        ):
            raise RuntimeError("MV-Scan finding emission accounting mismatch")
        print(
            "[mvscan-pairs] "
            + " ".join(
                f"{key}={pair_stats[key]}"
                for key in sorted(pair_stats)
            ),
            file=sys.stderr,
            flush=True,
        )

        # Return machine-readable JSON for a future dynamic exploit generator
        _record_json_unit(self, unit_id, pair_stats, json_findings)

        return results
