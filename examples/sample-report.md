# SoliGuard report

**SoliGuard v0.1.0** — heuristic Solidity static-analysis security linter.

Generated: 2026-10-15T02:09:39.175Z

> **Honesty notice:** SoliGuard is a heuristic pre-audit screening tool and is NOT a substitute for a professional security audit.
> Every finding below is a *potential* issue and requires manual review. False positives and false negatives are expected; nothing here replaces a professional audit.

## Summary

- Files scanned: 1
- Findings (at/above threshold): 21
  - critical: 1, warning: 11, info: 9
- Severity threshold (--min-severity): info
- Result: **FAIL** (exit code 1)

## Findings — examples/VulnerableToken.sol

### [info] floating-pragma — line 8

```solidity
pragma solidity ^0.8.17;
```

Floating pragma constraint ("^..."). The contract is not pinned to one compiler version, so identical source can compile to different bytecode across versions, making audits and reproducible builds unreliable. Pin an exact version (e.g. "pragma solidity 0.8.24;").

### [info] missing-visibility — line 15

```solidity
uint256 totalSupply;
```

State variable "totalSupply" has no explicit visibility (Solidity silently defaults to "internal"). Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.

### [info] missing-visibility — line 16

```solidity
mapping(address => uint256) balances;
```

State variable "balances" has no explicit visibility (Solidity silently defaults to "internal"). Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.

### [info] missing-visibility — line 17

```solidity
mapping(address => mapping(address => uint256)) allowances;
```

State variable "allowances" has no explicit visibility (Solidity silently defaults to "internal"). Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.

### [info] missing-visibility — line 19

```solidity
address owner;
```

State variable "owner" has no explicit visibility (Solidity silently defaults to "internal"). Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.

### [warning] hardcoded-address — line 20

```solidity
address hardcodedAdmin = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
```

Hardcoded address 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B found outside a named constant. If it participates in ownership/access control, the address is baked into the bytecode and every deployment instance is coupled to it — mistakes are costly and hard to audit across instances. Prefer a constructor parameter (with zero-address validation) or an explicitly documented named constant.

### [info] missing-visibility — line 20

```solidity
address hardcodedAdmin = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
```

State variable "hardcodedAdmin" has no explicit visibility (Solidity silently defaults to "internal"). Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.

### [warning] missing-zero-address-check — line 43

```solidity
function transfer(address to, uint256 amount) public returns (bool) {
```

Address parameter "to" is used but no address(0) check is visible in the function body. Address(0) can permanently lock funds or bypass access control. Consider require(to != address(0), "...") as the first statement of the function.

### [warning] missing-zero-address-check — line 48

```solidity
function approve(address spender, uint256 amount) external returns (bool) {
```

Address parameter "spender" is used but no address(0) check is visible in the function body. Address(0) can permanently lock funds or bypass access control. Consider require(spender != address(0), "...") as the first statement of the function.

### [warning] missing-zero-address-check — line 53

```solidity
function transferFrom(address from, address to, uint256 amount)
```

Address parameter "from" is used but no address(0) check is visible in the function body. Address(0) can permanently lock funds or bypass access control. Consider require(from != address(0), "...") as the first statement of the function.

### [warning] missing-zero-address-check — line 53

```solidity
function transferFrom(address from, address to, uint256 amount)
```

Address parameter "to" is used but no address(0) check is visible in the function body. Address(0) can permanently lock funds or bypass access control. Consider require(to != address(0), "...") as the first statement of the function.

### [warning] missing-zero-address-check — line 70

```solidity
function unguardedSetter(address beneficiary) external {
```

Address parameter "beneficiary" is used but no address(0) check is visible in the function body. Address(0) can permanently lock funds or bypass access control. Consider require(beneficiary != address(0), "...") as the first statement of the function.

### [warning] avoid-tx-origin — line 76

```solidity
require(tx.origin == owner, "not owner"); // auth via tx.origin
```

tx.origin is used. tx.origin is the account that originated the whole transaction, so a contract phished by that account can pass tx.origin checks the user never intended. For authorization, use msg.sender (the immediate caller) instead.

### [warning] unsafe-low-level-calls — line 77

```solidity
(bool ok, ) = owner.call{value: address(this).balance}("");
```

.call() used. .transfer()/.send() forward only 2300 gas and return a bool instead of reverting; .call()/.delegatecall() are raw low-level calls that also return a bool. Verify the returned value, avoid state changes after the call (checks-effects-interactions), and consider a reentrancy guard. Note: this heuristic can also match high-level ERC20 .transfer(.) calls, which are usually fine — review each hit.

### [info] missing-visibility — line 81

```solidity
function distribute(uint256 amount) {
```

Function "distribute()" has no explicit visibility (Solidity defaults to "public"). Declare public/private/internal/external explicitly — an accidentally public function is a classic attack surface.

### [warning] unbounded-loop — line 83

```solidity
for (uint256 i = 0; i < holders.length; i++) {
```

Loop condition "i < holders.length" does not reference a fixed literal or constant, so the loop is not provably bounded. If the bound depends on storage (e.g. a dynamic array length), the loop is unbounded: one transaction can exceed the block gas limit and permanently lock funds/state (DoS). Use a fixed bound or explicit pagination (cursor/chunking).

### [critical] selfdestruct-usage — line 89

```solidity
selfdestruct(payable(owner));
```

selfdestruct can delete the contract bytecode and force-send its balance to an address. It is deprecated: EIP-4758 planned its removal and EIP-6780 (Cancun) already restricts its effects, so relying on its semantics is fragile. Remove it unless contract destruction is an explicit, reviewed design goal.

### [warning] timestamp-dependence — line 93

```solidity
if (block.timestamp % 777 == 0) return 1; // timestamp-based logic
```

block.timestamp/now is used in a comparison. Timestamps are set by validators within a tolerance window, so strict equality or ordering logic can be influenced and behaves differently across chains. Do not rely on timestamps for randomness, prize/lottery logic, or security-critical ordering.

### [info] deprecated-keywords — line 98

```solidity
suicide(payable(owner)); // deprecated alias of selfdestruct
```

"suicide(...)" is the deprecated alias of selfdestruct. Replace it with selfdestruct or, better, remove self-destruction entirely — its semantics have changed across EVM forks (EIP-4758, EIP-6780).

### [warning] deprecated-keywords — line 102

```solidity
return blockhash(block.number - 1); // legacy randomness pattern
```

"blockhash(...)" is a legacy pattern: it only returns a meaningful value for the last 256 blocks and is weakly influenced by validators — unsafe for randomness/lotteries (EIP-4399 replaced it with prevrandao). Prefer a commit-reveal scheme or a verifiable random function (VRF).

### [info] assembly-usage — line 106

```solidity
assembly {
```

Inline assembly bypasses Solidity safety checks (bounds, overflow, reentrancy tooling) and is hard to audit. Keep it minimal, comment it as "audited assembly", and prefer plain Solidity where possible.

