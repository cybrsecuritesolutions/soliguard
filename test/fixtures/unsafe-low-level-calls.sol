// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: unsafe-low-level-calls
contract LowLevelCalls {
    function relay(address payable target) external payable {
        target.call{value: msg.value}("");
    }
}