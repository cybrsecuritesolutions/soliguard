// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: selfdestruct-usage (used by the directory-scan test)
contract Alpha {
    function nuke(address payable to) external {
        selfdestruct(to);
    }
}