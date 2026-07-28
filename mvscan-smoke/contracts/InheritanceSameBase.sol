// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SameBaseStorage {
    uint256 internal a;
    uint256 internal b;
}

contract InheritanceSameBase is SameBaseStorage {
    uint256 public result;

    function inspect() external {
        if (a < b) {
            result = 1;
        }
    }

    function updateA(uint256 value) external {
        a = value;
    }

    function updateB(uint256 value) external {
        b = value;
    }
}
