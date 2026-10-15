// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Negative control inside the directory-scan tree: zero findings.
contract Beta {
    address public owner;

    constructor(address _owner) {
        require(_owner != address(0), "owner is zero");
        owner = _owner;
    }
}