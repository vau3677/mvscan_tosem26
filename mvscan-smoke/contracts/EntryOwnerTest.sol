// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EntryOwnerTest {
    uint256 public a;
    uint256 public b;

    function writeViaA(uint256 value) external {
        _write(value);
    }

    function writeViaB(uint256 value) external {
        _write(value);
    }

    function inspect() external returns (uint256) {
        if (a > b) {
            b = b + 1;
        }

        return a;
    }

    function _write(uint256 value) internal {
        a = value;
    }

    function _unreachableWrite(uint256 value) internal {
        b = value;
    }
}