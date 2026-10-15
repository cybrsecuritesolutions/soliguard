// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: deprecated-keywords (blockhash case)
contract DeprecatedKeywords {
    function legacyHash() external view returns (bytes32) {
        return blockhash(block.number - 1);
    }
}