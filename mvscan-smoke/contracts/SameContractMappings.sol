// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SameContractMappings {
    mapping(address => uint256) private balances;
    mapping(address => uint256) private debts;
    uint256 public result;

    function inspect() external {
        if (balances[msg.sender] < debts[msg.sender]) {
            result = 1;
        }
    }

    function updateBalance(uint256 value) external {
        balances[msg.sender] = value;
    }

    function updateDebt(uint256 value) external {
        debts[msg.sender] = value;
    }
}
