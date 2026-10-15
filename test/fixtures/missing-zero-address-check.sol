// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: missing-zero-address-check
contract ZeroAddressCheck {
    address public admin;

    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }
}