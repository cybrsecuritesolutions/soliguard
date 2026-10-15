// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: missing-visibility (state variable + function)
contract MissingVisibility {
    uint256 counter;

    function tick() {
        counter = counter + 1;
    }
}