from __future__ import annotations
from types import SimpleNamespace
import mvscan_plugin.inconsistent_state as detector
from mvscan_plugin.utils.icfg import ICFG, function_key

def make_source(path: str, is_dependency: bool = False):
    filename = SimpleNamespace(
        relative=path,
        short=path,
        absolute=f"/repo/{path}",
    )
    return SimpleNamespace(
        filename=filename,
        is_dependency=is_dependency,
    )

class FakeContract:
    def __init__(self, name: str, path: str, *, is_dependency: bool = False, is_abstract: bool = False):
        self.name = name
        self.canonical_name = name
        self.source_mapping = make_source(path, is_dependency)
        self.functions_entry_points = []
        self.is_interface = False
        self.is_library = False
        self.is_abstract = is_abstract

class FakeFunction:
    def __init__(self, contract, declarer, name: str, path: str, node_id: int, *, visibility: str = "external", is_dependency: bool = False):
        self.contract = contract
        self.contract_declarer = declarer
        self.name = name
        self.full_name = f"{name}()"
        self.canonical_name = f"{declarer.name}.{self.full_name}"
        self.visibility = visibility
        self.is_constructor = False
        self.modifiers = []
        self.nodes = []
        self.entry_point = SimpleNamespace(node_id=node_id)
        self.source_mapping = make_source(path, is_dependency)

def empty_block(): return { "reads": set(), "writes": set(), "succ": set() }

def test_root_seeding():
    target = FakeContract("TargetToken", "contracts/TargetToken.sol")
    dependency = FakeContract("ERC20", "node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol", is_dependency=True)
    profiler = FakeContract("TargetTokenProfiler", "contracts/testing/profiling/TargetTokenProfiler.sol")
    target_run = FakeFunction(target, target, "run", "contracts/TargetToken.sol", 1)

    # Two contextual representations of the same inherited implementation:
    # one exposed by the first-party contract, one belonging to the dependency
    # contract itself.
    inherited_transfer = FakeFunction(
        target,
        dependency,
        "transfer",
        "node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol",
        2,
        is_dependency=True,
    )
    dependency_transfer = FakeFunction(
        dependency,
        dependency,
        "transfer",
        "node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol",
        2,
        is_dependency=True,
    )

    dependency_helper = FakeFunction(
        dependency,
        dependency,
        "_transfer",
        "node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol",
        3,
        visibility="internal",
        is_dependency=True,
    )

    profile_run = FakeFunction(
        profiler,
        profiler,
        "profileRun",
        "contracts/testing/profiling/TargetTokenProfiler.sol",
        4,
    )

    target.functions_entry_points = [
        target_run,
        inherited_transfer,
    ]
    dependency.functions_entry_points = [
        dependency_transfer,
    ]
    profiler.functions_entry_points = [
        profile_run,
    ]

    graph = ICFG()

    target_run_bid = (
        function_key(target_run),
        target_run.entry_point.node_id,
    )
    transfer_bid = (
        function_key(dependency_transfer),
        dependency_transfer.entry_point.node_id,
    )
    helper_bid = (
        function_key(dependency_helper),
        dependency_helper.entry_point.node_id,
    )
    profiler_bid = (
        function_key(profile_run),
        profile_run.entry_point.node_id,
    )

    graph.blocks = {
        target_run_bid: empty_block(),
        transfer_bid: empty_block(),
        helper_bid: empty_block(),
        profiler_bid: empty_block(),
    }

    # A first-party root calls into dependency implementation code
    graph.call_edges[target_run_bid].add(helper_bid)
    graph.fn_lookup = {
        function_key(target_run): target_run,
        function_key(dependency_transfer): dependency_transfer,
        function_key(dependency_helper): dependency_helper,
        function_key(profile_run): profile_run,
    }
    compilation_unit = SimpleNamespace(
        contracts=[
            target,
            dependency,
            profiler,
        ]
    )

    old_always = set(detector.USER_CALLABLE_ALWAYS)
    old_deny = set(detector.USER_CALLABLE_DENY)

    try:
        detector.USER_CALLABLE_ALWAYS.clear()
        detector.USER_CALLABLE_DENY.clear()
        owners = detector.compute_entry_owners(
            graph,
            compilation_unit,
        )
    finally:
        detector.USER_CALLABLE_ALWAYS.clear()
        detector.USER_CALLABLE_ALWAYS.update(old_always)

        detector.USER_CALLABLE_DENY.clear()
        detector.USER_CALLABLE_DENY.update(old_deny)

    target_run_owner = detector._root_owner_key(
        target,
        target_run,
    )
    inherited_transfer_owner = detector._root_owner_key(
        target,
        inherited_transfer,
    )
    standalone_dependency_owner = detector._root_owner_key(
        dependency,
        dependency_transfer,
    )

    # Ordinary first-party entrypoint is retained.
    assert target_run_owner in owners[target_run_bid]

    # Dependency implementation remains reachable through a first-party call.
    assert target_run_owner in owners[helper_bid]

    # Inherited public API remains present, but under first-party identity.
    assert inherited_transfer_owner in owners[transfer_bid]

    # Dependency contract is not independently seeded.
    assert standalone_dependency_owner not in owners[transfer_bid]

    # Frozen root seeding retains first-party APIs; source-scope filtering
    # happens when constructing the evaluation candidate union.
    assert profiler_bid in owners

    all_owner_names = {
        owner
        for owner_set in owners.values()
        for owner in owner_set
    }

    assert not any(
        owner.startswith("node_modules/")
        for owner in all_owner_names
    )
    assert any(
        "contracts/testing/" in owner
        for owner in all_owner_names
    )

def main():
    test_root_seeding()
    print("PASS: dependency roots excluded; first-party roots retained for later scope filtering")
    print("PASS: inherited first-party APIs remain seeded")
    print("PASS: dependency callees remain reachable")

if __name__ == "__main__": main()