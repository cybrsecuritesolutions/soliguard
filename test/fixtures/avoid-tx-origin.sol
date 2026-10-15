// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Fires: avoid-tx-origin
contract TxOriginAuth {
    address public owner;

    constructor(address _owner) {
        require(_owner != address(0), "zero");
        owner = _owner;
    }

    function guarded() external {
        require(tx.origin == owner, "not owner");
    }
}