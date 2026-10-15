# SoliGuard rules (v0.1)

Every rule below is a **heuristic**: it scans source text for a pattern and reports a *potential* issue. It does **not** prove the issue exists, and it cannot prove that anything else is safe. Severity order: `info` < `warning` < `critical`.

All findings carry: stable rule id, severity, line number, source snippet, plain-language explanation.

---

## 1. `avoid-tx-origin` — warning

**Detects:** any use of `tx.origin`.

**Why it matters:** `tx.origin` is the EOA that initiated the *entire* transaction — not the immediate caller. A contract that checks `require(tx.origin == owner)` can be defeated by a malicious contract that the owner's EOA was phished into calling: the phish contract calls your contract, and `tx.origin` is still the owner's EOA. Use `msg.sender` for authorization.

**Example:**
```solidity
require(tx.origin == owner, "not owner");
```

---

## 2. `unsafe-low-level-calls` — warning

**Detects:** `.call(`, `.delegatecall(`, `.send(`, `.transfer(` invocations.

**Why it matters:** `.transfer()`/`.send()` forward only 2300 gas, return a bool, and do **not** revert on failure. `.call()`/`.delegatecall()` are raw low-level calls that also return a bool the caller must check. Combined with state changes after the call, these are a classic reentrancy vector. Check the returned value, apply checks-effects-interactions, or add a reentrancy guard.

**Example:**
```solidity
(bool ok, ) = owner.call{value: address(this).balance}("");
require(ok, "call failed");
```

**Caveat:** this heuristic also matches high-level ERC-20 `.transfer(...)` calls, which are usually fine. Review each hit — the finding message says so too.

---

## 3. `floating-pragma` — info

**Detects:** `pragma solidity` constraints like `^0.8.x`, `>=0.8.0 <0.9.0`.

**Why it matters:** a non-pinned compiler constraint means the same source can compile to different bytecode on different toolchains. That makes reproducible builds and audits unreliable. Pin an exact version, e.g. `pragma solidity 0.8.24;`.

**Example:**
```solidity
pragma solidity ^0.8.17;   // -> floating
pragma solidity 0.8.24;    // -> ok
```

---

## 4. `missing-zero-address-check` — warning

**Detects:** `constructor`/`external`/`public` functions that use an `address` parameter with no `address(0)` guard visible in the function body. Parameter must actually be used in the body (unused params are ignored), body comments are stripped, and `view`/`pure` functions are skipped.

**Why it matters:** assigning or sending value to `address(0)` permanently locks funds; using it in access control can bypass checks. `require(x != address(0), ...)` as the first statement is the fix.

**Example:** flagged
```solidity
function unguardedSetter(address beneficiary) external {
    balances[beneficiary] += 100;
}
```
not flagged:
```solidity
function setOwner(address newOwner) external {
    require(newOwner != address(0), "zero address");
    owner = newOwner;
}
```

**Caveats:** `internal`/`private` helpers are skipped by design (validation should happen at the entry points). Validation written in a form the scanner doesn't recognize (e.g. `require(newOwner == address(0), "no"); revert();`-style) may cause a false positive — review before acting.

---

## 5. `unbounded-loop` — warning

**Detects:** `for` loops whose condition does not reference a numeric literal — i.e. loops that are not provably bounded by a constant.

**Why it matters:** if the bound depends on storage (a dynamic array length, a count that grows with users), the loop is unbounded: a single transaction can consume more than a block's gas and permanently lock funds/state (a DoS). Guard with a fixed cap or paginate with an explicit cursor.

**Example:**
```solidity
for (uint256 i = 0; i < holders.length; i++) {   // flagged: bound is storage-dependent
for (uint256 i = 0; i < 10; i++) {               // not flagged: literal bound
```
Multi-line loop headers may be missed (heuristic is line-oriented).

---

## 6. `selfdestruct-usage` — critical

**Detects:** `selfdestruct(...)`.

**Why it matters:** `selfdestruct` can delete the contract's bytecode and force-send its whole balance. It is deprecated: EIP-4758 planned its removal and EIP-6780 (Cancun) already restricted its effects, so relying on its semantics is fragile across EVM upgrades. Remove it unless contract destruction is an explicit, reviewed design goal.

**Example:**
```solidity
function kill() external onlyOwner {
    selfdestruct(payable(owner));
}
```

---

## 7. `hardcoded-address` — warning

**Detects:** raw `0x` + 40-hex address literals that are not part of a `constant` declaration.

**Why it matters:** an address baked into ownership/access-control logic ties every deployment to one entity and makes mistakes costly and hard to audit across instances. Prefer a constructor parameter (with a zero-address check) or a clearly documented named constant.

**Example:**
```solidity
address hardcodedAdmin = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;  // flagged
address public constant SAFE = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B; // not flagged
```

---

## 8. `timestamp-dependence` — warning

**Detects:** `block.timestamp` (or the legacy `now`) used together with a comparison operator (`==`, `!=`, `<`, `>`, `<=`, `>=`).

**Why it matters:** timestamps are set by validators within a tolerance window (and are trivially influenced for meaningful windows on some chains). Strict equality/ordering logic can be manipulated and behaves differently across chains. Do not use timestamps for randomness, prize logic, or security-critical ordering.

**Example:**
```solidity
if (block.timestamp % 777 == 0) return 1;   // flagged
```

---

## 9. `missing-visibility` — info

**Detects:** state variables at contract scope and `function` declarations without an explicit `public`/`private`/`internal`/`external` keyword.

**Why it matters:** Solidity silently defaults state variables to `internal` and functions to `public`. Silent defaults hide intent: an accidentally public function is a classic attack surface; an accidentally internal variable can't be read by tools/users that need it. Write it explicitly.

**Example:**
```solidity
uint256 totalSupply;                   // flagged (defaults internal)
address public owner;                  // not flagged
function distribute(uint256 amount) {  // flagged (defaults public)
function distribute(uint256 amount) external {  // not flagged
```

---

## 10. `deprecated-keywords` — info / warning

**Detects:**
- `suicide(...)` — the deprecated alias of `selfdestruct` — **info**.
- `blockhash(...)` — a legacy pattern — **warning**.

**Why it matters:** `suicide` is a deprecated alias whose semantics keep changing across EVM forks (EIP-4758, EIP-6780). `blockhash` is only meaningful for the last 256 blocks and is weakly influenced by validators, making it unsafe for randomness/lotteries (EIP-4399 replaced it with `prevrandao`).

**Example:**
```solidity
suicide(payable(owner));                  // info
return blockhash(block.number - 1);       // warning
```

---

## 11. `assembly-usage` — info

**Detects:** inline `assembly { ... }` blocks.

**Why it matters:** inline assembly bypasses Solidity's safety checks (bounds, overflow checks, reentrancy tooling) and is hard to audit. Keep it minimal, mark it as audited, and prefer plain Solidity where possible.

**Example:**
```solidity
function tweak() external pure returns (uint256 x) {
    assembly { x := 42 }
}
```