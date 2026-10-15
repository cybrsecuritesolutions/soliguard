// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: selfdestruct-usage
contract SelfDestruct {
    function destroy(address payable to) external {
        selfdestruct(to);
    }
}