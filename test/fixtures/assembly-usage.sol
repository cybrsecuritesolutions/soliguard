// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: assembly-usage
contract AssemblyUsage {
    function get() external pure returns (uint256 x) {
        assembly {
            x := 42
        }
    }
}