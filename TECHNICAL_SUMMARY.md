# SoliGuard — Technical Summary (v0.1)

*This document is the factual core of GrantForge's first grant application. Every
claim in it is verifiable by running the tool in this repository. Nothing here is
estimated, extrapolated, or aspirational — see "What this version actually does"
and "Limitations" below for the honest boundaries.*

## Project overview

**SoliGuard** is an open-source, dependency-free heuristic static-analysis
security linter for Solidity smart contracts. It is the first tool built by
**GrantForge**, an open-source Web3 developer-tools project funded through
ecosystem grants (BNB Chain builder programs, Gitcoin rounds, retroactive
funding, DAO treasuries). Grant proceeds settle to the project's designated
BEP-20 treasury wallet
`0x095a9Dac23411427895CA4d62B353540fC258525`.

SoliGuard is deliberately small and honest: it is a **pre-audit screening tool**,
documented as such, and it does not pretend to be a professional security audit.
The linter is a single Node.js file (`soliguard.js`, ~600 lines) with **zero
runtime dependencies** — it runs on any stock Node.js ≥ 18 with `node
soliguard.js <file.sol | dir>`. This makes it trivially auditable (the entire
tool is one readable source file) and trivially portable to CI.

## What this version actually does

- Scans one `.sol` file or recursively walks a directory.
- Applies **11 heuristic rules** (full list below) and emits, per finding: a
  **stable rule id**, a **severity** (`info`/`warning`/`critical`), the
  **line number**, a **snippet** of the matched source, and a plain-language
  explanation of the risk.
- Reports as **Markdown-style text by default** or **JSON** with `--json`.
- Supports `--min-severity info|warning|critical` (default `info`) to filter
  findings and drive exit code.
- **Exit codes:** `0` = no findings at/above threshold (PASS), `1` = findings
  exist (FAIL, CI-usable), `2` = usage/input error.
- Every report carries the honesty notice: *"SoliGuard is a heuristic pre-audit
  screening tool and is NOT a substitute for a professional security audit."*

### Implemented rules (v0.1, exact)

| # | Rule id | Severity | Pattern detected |
|---|---------|----------|------------------|
| 1 | `avoid-tx-origin` | warning | `tx.origin` anywhere |
| 2 | `unsafe-low-level-calls` | warning | `.call` / `.delegatecall` / `.send` / `.transfer` |
| 3 | `floating-pragma` | info | non-pinned pragma (`^`, `>=`, `<`, …) |
| 4 | `missing-zero-address-check` | warning | used address param without `address(0)` guard (constructor/external/public fns; internal/private and view/pure skipped) |
| 5 | `unbounded-loop` | warning | `for` loop condition with no numeric literal |
| 6 | `selfdestruct-usage` | critical | `selfdestruct(...)` |
| 7 | `hardcoded-address` | warning | `0x`+40-hex literal outside a `constant` |
| 8 | `timestamp-dependence` | warning | `block.timestamp`/`now` with a comparison operator |
| 9 | `missing-visibility` | info | state var or function without explicit visibility |
| 10 | `deprecated-keywords` | info (suicide) / warning (blockhash) | `suicide(...)` alias; `blockhash(...)` |
| 11 | `assembly-usage` | info | inline `assembly { }` |

All 11 rules are implemented, exercised against the sample fixture
(`examples/VulnerableToken.sol`), and every match was inspected by hand during
development: the fixture triggers **all 11 rules, 21 findings total
(1 critical, 11 warning, 9 info)**. The real generated report is committed at
`examples/sample-report.md` (JSON: `examples/sample-report.json`). The fixture
also contains a deliberate negative control (`setOwner` with a proper
`address(0)` check) that the scanner must *not* flag, verified during development.

### How to run it (verifiable)

```bash
node soliguard.js examples/VulnerableToken.sol            # text report, exit 1
node soliguard.js examples/VulnerableToken.sol --json     # JSON report
node soliguard.js examples/VulnerableToken.sol --min-severity critical
node soliguard.js contracts/                              # scan a directory
```

## Honest limitations

1. **Heuristic, not exhaustive.** SoliGuard is a pattern scanner with no
   data-flow or symbolic analysis. It cannot reason about values, paths, or
   compositions of issues.
2. **False positives.** E.g. `unsafe-low-level-calls` can match ERC-20
   `.transfer(...)` (usually fine); `missing-zero-address-check` can miss
   unusual validation styles; a comment can influence a heuristic.
3. **False negatives.** Anything outside the 11 rules — overflow/underflow
   logic, complex reentrancy paths, access-control design, upgradeability,
   oracle reliance — is not scanned at all. A clean report ≠ secure contract.
4. **Line-oriented heuristics.** Multi-line constructs (multi-line `for`
   headers, spread-out signatures) can be missed.
5. **Not an audit.** SoliGuard screens *before* an audit; it never replaces one.

## Proposed roadmap (future milestones)

These are *plans*, not shipped features — they will be reported on only when
they exist and pass the same run-it-yourself test:

- **v0.2 — SARIF output** (`--sarif`) for native GitHub Code Scanning / CI
  integration, plus `--format table` for terminals.
- **v0.2 — rule set expansion:** checks-effects-interactions (state-write-after-
  external-call) heuristic, unchecked return values of low-level calls,
  `external` calls inside loops, `require`-style validation detection for
  `missing-zero-address-check` (fewer false positives), `msg.value` misuse.
- **v0.3 — CI integration:** official GitHub Action + reusable GitLab/CI
  snippets; thresholds plug into merge-gates (`--min-severity` already exists).
- **v0.3 — Foundry/Hardhat plugins** so `soliguard` becomes `forge lint`-able.
- **v0.4 — Parser-grade analysis:** replace line heuristics with a lightweight
  Solidity tokenizer for multi-line constructs and control-flow context.
- **Always:** keep the tool single-file, zero-dependency, and MIT-licensed;
  publish release artifacts (tarball + npm package) with signed checksums.

## Repository layout (v0.1)

```
soliguard.js                  the entire linter (zero dependencies)
package.json                  metadata, bin entry, lint scripts
README.md                     user docs + rule table + limitations
RULES.md                      per-rule detail and examples
TECHNICAL_SUMMARY.md          this document
LICENSE                       MIT
examples/VulnerableToken.sol  intentionally vulnerable sample fixture
examples/sample-report.md     real generated report (committed output of v0.1)
examples/sample-report.json   real generated JSON report
```