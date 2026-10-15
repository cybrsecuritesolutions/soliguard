// SPDX-License-Identifier: MIT
// SoliGuard sample fixture — an intentionally vulnerable ERC-20-like token.
// DO NOT use this code in production. Every finding in sample-report.md
// corresponds to a real issue in this file: bad auth, unsafe calls,
// missing validation, unbounded loops, self-destruction, hardcoded
// addresses, timestamp dependence, missing visibility and legacy keywords.

pragma solidity ^0.8.17;

contract VulnerableToken {
    string public name = "SoliGuard Demo Token";
    string public symbol = "SGD";
    uint8 public decimals = 18;

    uint256 totalSupply;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowances;

    address owner;
    address hardcodedAdmin = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
    uint256 public constant cap = 1_000_000 * 10 ** 18;
    address[] public holders;

    event Transfer(address indexed from, address indexed to, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        balances[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balances[from] >= amount, "insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        require(allowances[from][msg.sender] >= amount, "allowance exceeded");
        allowances[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function setOwner(address newOwner) external {
        // Negative control: this one IS validated on purpose, so the
        // missing-zero-address rule must NOT flag it.
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }

    function unguardedSetter(address beneficiary) external {
        balances[beneficiary] += 100; // no address(0) check: any caller can
        // credit address(0) and lock value in it.
    }

    function withdrawAll() external {
        require(tx.origin == owner, "not owner"); // auth via tx.origin
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "call failed");
    }

    function distribute(uint256 amount) {
        // Loop bound is a storage array length: loop is not provably bounded.
        for (uint256 i = 0; i < holders.length; i++) {
            balances[holders[i]] += amount;
        }
    }

    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }

    function roll() external view returns (uint256) {
        if (block.timestamp % 777 == 0) return 1; // timestamp-based logic
        return 0;
    }

    function legacy() external {
        suicide(payable(owner)); // deprecated alias of selfdestruct
    }

    function legacyHash() external view returns (bytes32) {
        return blockhash(block.number - 1); // legacy randomness pattern
    }

    function tweak() external pure returns (uint256 x) {
        assembly {
            x := 42
        }
    }
}