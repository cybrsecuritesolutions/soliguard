// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: timestamp-dependence
contract TimestampDependence {
    uint256 public deadline;

    function claim() external {
        require(block.timestamp > deadline, "too early");
    }
}