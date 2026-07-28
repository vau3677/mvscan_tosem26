// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SingleVariable {
    uint256 private value;
    uint256 public result;

    function inspect() external {
        if (value > 0) {
            result = 1;
        }
    }

    function updateValue(uint256 newValue) external {
        value = newValue;
    }
}
