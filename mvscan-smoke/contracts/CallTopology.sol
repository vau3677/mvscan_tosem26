// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CallTopology {
    uint256 x;

    function entryA() external {
        _shared();
        x += 1;
    }

    function entryB() external {
        _shared();
        x += 2;
    }

    function _shared() internal {
        x = 7;
    }
}
