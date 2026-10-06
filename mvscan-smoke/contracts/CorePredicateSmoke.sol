// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CorePredicateSmoke {
    uint256 private a;
    uint256 private b;
    uint256 public result;

    function updateA(uint256 value) external { a = value; }
    function noopA() external { a = a; }
    function updateBoth(uint256 left, uint256 right) external { a = left; b = right; }

    function consumeAOnly() external { if (a > 0) result = 1; }
    function consumeRelation() external { if (a < b) result = 2; }
}
