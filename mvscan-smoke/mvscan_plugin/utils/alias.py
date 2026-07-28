"""
alias.py
Canonicalises every external call as a key and maps that key to the concrete state variable (or slot wrapper) it aliases
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Set

@dataclass(frozen=True, slots=True)
class AliasKey:
    addr: str
    selector: str
    args: tuple[str, ...]

# Maps each AliasKey to a unique ExternalStateVar wrapper
class AliasRegistry:
    def __init__(self):
        self._key_to_var: Dict[AliasKey, Any] = {}
        self._var_to_keys: Dict[Any, Set[AliasKey]] = defaultdict(set)

    @staticmethod
    def _canon(addr, selector, args) -> AliasKey:
        return AliasKey(
            (addr or "self").lower(),
            selector.lower(),
            tuple(str(arg) for arg in args),
        )

    # Return the unique wrapper for this call-site, create if new
    def get_or_create(self, addr, selector, args, wrapper_ctor):
        k = self._canon(addr, selector, args)
        if k not in self._key_to_var: self._key_to_var[k] = wrapper_ctor()
        v = self._key_to_var[k]
        self._var_to_keys[v].add(k)
        return v

    def clear(self) -> None:
        self._key_to_var.clear()
        self._var_to_keys.clear()

ALIAS_REG = AliasRegistry()
