// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: unbounded-loop
contract UnboundedLoop {
    address[] public users;

    function touchAll() external {
        for (uint256 i = 0; i < users.length; i++) {
            users[i] = users[i];
        }
    }
}