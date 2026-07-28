// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SourceState {
    uint256 private a;
    uint256 private b;

    function quote() external view returns (uint256) {
        return a + b;
    }

    function updateA(uint256 value) external {
        a = value;
    }

    function updateB(uint256 value) external {
        b = value;
    }
}

contract ConsumerState {
    SourceState public source;
    uint256 private limit;
    uint256 public result;

    function setSource(SourceState newSource) external {
        source = newSource;
    }

    function inspect() external {
        if (source.quote() < limit) {
            result = 1;
        }
    }

    function updateLimit(uint256 value) external {
        limit = value;
    }
}
