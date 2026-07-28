from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable
import mvscan_plugin.utils.icfg as icfg_module
from mvscan_plugin.utils.icfg import ICFG, stale_read_pairs

@dataclass(frozen=True)
class FakeVar:
    name: str
    canonical_name: str

@dataclass
class FakeFunction:
    name: str
    is_constructor: bool = False
    nodes: tuple = ()

def make_graph(variable: FakeVar, writer_bids, reader_bids, successors=None, writer_also_reads=False) -> ICFG:
    graph = ICFG()
    writer_bids = list(writer_bids)
    reader_bids = list(reader_bids)
    successors = successors or {}

    function_keys = { bid[0] for bid in writer_bids + reader_bids }
    graph.fn_lookup = {
        function_key: FakeFunction(name=function_key.rsplit("::", 1)[-1])
        for function_key in function_keys
    }

    graph.var_writes[variable] = set(writer_bids)
    graph.var_reads[variable] = set(reader_bids)

    if writer_also_reads: graph.var_reads[variable].update(writer_bids)

    all_bids = set(writer_bids) | set(reader_bids)

    for bid in all_bids:
        reads = set()

        if bid in graph.var_reads[variable]:
            reads.add(variable)

        writes = set()

        if bid in graph.var_writes[variable]:
            writes.add(variable)

        graph.blocks[bid] = {
            "reads": reads,
            "writes": writes,
            "succ": set(successors.get(bid, set())),
        }

    # This suite isolates exact witness enumeration. Real sensitive-read
    # facts require SlithIR SSA, which these fake graphs intentionally omit.
    graph.read_event_is_sensitive = (
        lambda bid, candidate_var: (
            bid in graph.var_reads.get(candidate_var, set())
        )
    )

    return graph

def witness_signature(witness):
    return (
        witness.writer_bid,
        witness.reader_bid,
        witness.operation_pattern,
        witness.writer_reaches_reader,
        witness.reader_reaches_writer,
    )

def test_multiple_reader_blocks_survive() -> None:
    variable = FakeVar("x", "Test.x")

    writer = ("contracts/Test.sol::Test.write(uint256)", 10)
    reader_1 = ("contracts/Test.sol::Test.consume(bool)", 20)
    reader_2 = ("contracts/Test.sol::Test.consume(bool)", 30)

    graph = make_graph(
        variable,
        writer_bids=[writer],
        reader_bids=[reader_1, reader_2],
    )

    witnesses = list(stale_read_pairs(graph))

    exact_pairs = {
        (witness.writer_bid, witness.reader_bid)
        for witness in witnesses
    }

    assert exact_pairs == {
        (writer, reader_1),
        (writer, reader_2),
    }, exact_pairs

def test_read_modify_write_does_not_suppress_later_reader() -> None:
    variable = FakeVar("balance", "Test.balance")

    writer = ("contracts/Test.sol::Test.increment()", 10)
    later_reader = ("contracts/Test.sol::Test.consume()", 20)

    graph = make_graph(
        variable,
        writer_bids=[writer],
        reader_bids=[later_reader],
        writer_also_reads=True,
    )

    witnesses = list(stale_read_pairs(graph))

    exact_pairs = {
        (witness.writer_bid, witness.reader_bid)
        for witness in witnesses
    }

    # The same-block writer/read witness is skipped, but the writer's
    # relationship with the other reader block must survive.
    assert exact_pairs == {
        (writer, later_reader),
    }, exact_pairs

def test_cfg_order_replaces_node_id_order() -> None:
    variable = FakeVar("counter", "Test.counter")

    function_key = "contracts/Test.sol::Test.updateAndConsume()"

    # Deliberately give the writer a larger node ID. Tuple comparison would
    # incorrectly classify this as destructive_write even though the CFG
    # says writer -> reader.
    writer = (function_key, 100)
    reader = (function_key, 2)

    graph = make_graph(
        variable,
        writer_bids=[writer],
        reader_bids=[reader],
        successors={
            writer: {reader},
            reader: set(),
        },
    )

    witnesses = list(stale_read_pairs(graph))

    assert len(witnesses) == 1

    witness = witnesses[0]

    assert witness.operation_pattern == "stale_read"
    assert witness.writer_reaches_reader is True
    assert witness.reader_reaches_writer is False

def test_enumeration_is_independent_of_mapping_insertion_order() -> None:
    alpha = FakeVar("alpha", "Test.alpha")
    beta = FakeVar("beta", "Test.beta")

    alpha_writer = ("contracts/Test.sol::Test.writeAlpha()", 11)
    alpha_reader = ("contracts/Test.sol::Test.readAlpha()", 21)

    beta_writer = ("contracts/Test.sol::Test.writeBeta()", 12)
    beta_reader = ("contracts/Test.sol::Test.readBeta()", 22)

    graph_a = make_graph(
        alpha,
        writer_bids=[alpha_writer],
        reader_bids=[alpha_reader],
    )

    beta_graph_a = make_graph(
        beta,
        writer_bids=[beta_writer],
        reader_bids=[beta_reader],
    )

    graph_a.var_writes.update(beta_graph_a.var_writes)
    graph_a.var_reads.update(beta_graph_a.var_reads)
    graph_a.var_to_branchgroups.update(
        beta_graph_a.var_to_branchgroups
    )
    graph_a.fn_lookup.update(beta_graph_a.fn_lookup)
    graph_a.blocks.update(beta_graph_a.blocks)

    graph_b = make_graph(
        beta,
        writer_bids=[beta_writer],
        reader_bids=[beta_reader],
    )

    alpha_graph_b = make_graph(
        alpha,
        writer_bids=[alpha_writer],
        reader_bids=[alpha_reader],
    )

    graph_b.var_writes.update(alpha_graph_b.var_writes)
    graph_b.var_reads.update(alpha_graph_b.var_reads)
    graph_b.var_to_branchgroups.update(
        alpha_graph_b.var_to_branchgroups
    )
    graph_b.fn_lookup.update(alpha_graph_b.fn_lookup)
    graph_b.blocks.update(alpha_graph_b.blocks)

    result_a = [
        witness_signature(witness)
        for witness in stale_read_pairs(graph_a)
    ]

    result_b = [
        witness_signature(witness)
        for witness in stale_read_pairs(graph_b)
    ]

    assert result_a == result_b, (result_a, result_b)


def main() -> None:
    # Keep this unit test focused on exact witness enumeration.
    original_noop_filter = icfg_module.NOOP_WRITE_FILTER
    original_same_key = icfg_module.REQUIRE_SAME_SLOT_KEY

    try:
        icfg_module.NOOP_WRITE_FILTER = False
        icfg_module.REQUIRE_SAME_SLOT_KEY = False

        test_multiple_reader_blocks_survive()
        print("PASS: multiple reader blocks survive")

        test_read_modify_write_does_not_suppress_later_reader()
        print("PASS: read-modify-write preserves later reader")

        test_cfg_order_replaces_node_id_order()
        print("PASS: CFG order replaces tuple order")

        test_enumeration_is_independent_of_mapping_insertion_order()
        print("PASS: insertion-order invariance")

    finally:
        icfg_module.NOOP_WRITE_FILTER = original_noop_filter
        icfg_module.REQUIRE_SAME_SLOT_KEY = original_same_key

    print("\nALL EXACT-WITNESS TESTS PASSED")


if __name__ == "__main__":
    main()