// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Negative control: this contract must produce ZERO findings.
contract CleanContract {
    address public owner;

    constructor(address _owner) {
        require(_owner != address(0), "owner is zero");
        owner = _owner;
    }

    function setOwner(address _newOwner) external returns (bool) {
        require(_newOwner != address(0), "owner is zero");
        owner = _newOwner;
        return true;
    }
}