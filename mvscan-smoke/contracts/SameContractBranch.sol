// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SameContractBranch {
    uint256 private a;
    uint256 private b;
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
