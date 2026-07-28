// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OrderTest {
    uint256 private a;
    uint256 private b;
    uint256 public flag;

    // Caller is deliberately declared before the callee.
    function inspect() external returns (bool) {
        (uint256 x, uint256 y) = snapshot();

        if (x < y) {
            flag = 1;
        }

        return x < y;
    }

    function updateA(uint256 value) external {
        a = value;
    }

    function updateB(uint256 value) external {
        b = value;
    }

    function snapshot()
        internal
        view
        returns (uint256, uint256)
    {
        return (a, b);
    }
}
