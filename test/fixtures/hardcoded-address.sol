// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: hardcoded-address
contract HardcodedAddress {
    function check() external pure returns (bool) {
        return msg.sender == 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
    }
}