from types import SimpleNamespace

import mvscan_plugin.inconsistent_state as detector
import mvscan_plugin.utils.icfg as icfg_module


class Flag:
    def __init__(self, **values):
        self.__dict__.update(values)


def test_direct_call_target_is_canonicalized(monkeypatch):
    physical = Flag(entry_point=object())
    contextual = Flag(entry_point=object())
    graph = icfg_module.ICFG()
    monkeypatch.setattr(icfg_module, "function_key", lambda _fn: "physical-key")
    graph.fn_lookup["physical-key"] = physical
    assert graph.resolve_call_functions(Flag(function=contextual), None) == (physical,)


def test_function_identity_uses_solidity_signature_and_selector():
    fn = Flag(
        contract_declarer=Flag(name="Vault"),
        solidity_signature="withdraw(address,uint256)",
        full_name="ignored()",
        visibility="external",
        is_constructor=False,
        is_fallback=False,
        is_receive=False,
    )
    pretty, selector = detector.fn_id(fn)
    assert pretty == "Vault.withdraw(address,uint256)"
    assert selector.startswith("0x") and len(selector) == 10


def test_missing_source_lines_are_reported_as_zero():
    bid = ("f", 1)
    graph = SimpleNamespace(
        node_lookup={
            bid: Flag(
                source_mapping=Flag(
                    lines=[],
                    filename=Flag(relative="contracts/Vault.sol", short="Vault.sol"),
                )
            )
        }
    )
    assert detector.src(bid, graph) == ("contracts/Vault.sol", 0)
