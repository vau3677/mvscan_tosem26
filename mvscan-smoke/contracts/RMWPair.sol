// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RMWPair {
    uint256 private counter;
    uint256 private observed;

    // The counter write is a read-modify-write:
    // this block both reads and writes counter.
    function increment() external {
        counter = counter + 1;
    }

    // A distinct externally callable transaction reads counter
    // and uses its value in a state update.
    function consume() external {
        observed = counter;
    }
}

contract RMWOnly {
    uint256 private counter;

    // Negative control: the identical static block should not
    // be paired with itself merely because it reads and writes.
    function incrementOnly() external {
        counter = counter + 1;
    }
}
