import mvscan_plugin.utils.icfg as icfg_module


class FakeVar:
    name = "counter"


class FakeFunction:
    def __init__(self, name):
        self.name = name
        self.full_name = f"{name}()"
        self.is_constructor = False
        self.nodes = []
        self.state_mutability = "nonpayable"


class FakeICFG:
    def __init__(self, var, writer, reader):
        self.var_writes = {var: {writer}}
        self.var_reads = {var: {writer, reader}}
        self.fn_lookup = {
            writer[0]: FakeFunction("increment"),
            reader[0]: FakeFunction("consume"),
        }
        self.blocks = {
            writer: {
                "reads": {var},
                "writes": {var},
                "succ": set(),
            },
            reader: {
                "reads": {var},
                "writes": set(),
                "succ": set(),
            },
        }


def test_read_modify_write_block_can_pair_with_other_reader(monkeypatch):
    var = FakeVar()
    writer = ("RMWPair.increment()", 1)
    reader = ("RMWPair.consume()", 2)
    graph = FakeICFG(var, writer, reader)
    graph.read_event_is_sensitive = (lambda _bid, _var: True)

    monkeypatch.setattr(icfg_module, "INCLUDE_SCALAR_WITNESSES", True)
    monkeypatch.setattr(icfg_module, "NOOP_WRITE_FILTER", False)
    monkeypatch.setattr(icfg_module, "REQUIRE_SAME_SLOT_KEY", False)

    pairs = list(icfg_module.stale_read_pairs(graph))

    assert any(
        witness.writer_bid == writer
        and witness.reader_bid == reader
        and witness.variable is var
        for witness in pairs
    )


def test_identical_static_block_pair_is_skipped(monkeypatch):
    var = FakeVar()
    block = ("RMWPair.increment()", 1)
    graph = FakeICFG(var, block, block)
    graph.read_event_is_sensitive = (lambda _bid, _var: True)

    monkeypatch.setattr(icfg_module, "INCLUDE_SCALAR_WITNESSES", True)
    monkeypatch.setattr(icfg_module, "NOOP_WRITE_FILTER", False)
    monkeypatch.setattr(icfg_module, "REQUIRE_SAME_SLOT_KEY", False)

    assert list(icfg_module.stale_read_pairs(graph)) == []
