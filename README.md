# SoliGuard

**A lightweight, dependency-free, heuristic Solidity static-analysis security linter — pre-audit screening for smart-contract developers.**

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D%2018-brightgreen.svg)
[![CI: GitHub Actions](https://img.shields.io/github/actions/workflow/status/cybrsecuritesolutions/soliguard/ci.yml)](.github/workflows/ci.yml)

SoliGuard scans Solidity source for common vulnerability patterns and reports them with line numbers, severity, and actionable explanations. It runs on plain Node.js >= 18 — zero runtime dependencies, no compiler required.

> **Honesty notice:** SoliGuard is a **heuristic** tool. It flags *potential* issues; false positives and false negatives are expected. It is a pre-audit screening aid — **not** a substitute for a professional security audit.

## Features

- **11 heuristic rules** covering the most common Solidity pitfalls (see the [rule table](#rules))
- **Zero dependencies** — one CLI file, plain Node.js >= 18
- **Human-readable reports** (Markdown-style) and **machine-readable JSON** (`--json`)
- **Severity filtering** (`--min-severity info|warning|critical`)
- **Recursive directory scanning**
- **Predictable exit codes** for CI pipelines (`0` clean, `1` findings, `2` usage error)

## Quickstart

```bash
# run on a single file
node soliguard.js path/to/Contract.sol

# run on a directory (recursive)
node soliguard.js contracts/

# machine-readable JSON output
node soliguard.js contracts/ --json

# only report findings at or above a severity
node soliguard.js Contract.sol --min-severity critical

# list the implemented rules
node soliguard.js --rules

# run the test suite
npm test
```

### Exit codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | Scan completed, no findings at/above the severity threshold |
| `1`  | Scan completed, findings exist at/above the threshold    |
| `2`  | Usage or input error (bad flag, missing path, unreadable file) |

## Rules

| Rule ID                     | Severity | What it catches                                                       |
| --------------------------- | -------- | --------------------------------------------------------------------- |
| `avoid-tx-origin`           | warning  | `tx.origin` used as an authorization signal (phishing/impersonation)  |
| `unsafe-low-level-calls`    | warning  | `.call` / `.delegatecall` / `.send` / `.transfer` — unchecked failures, reentrancy vectors |
| `floating-pragma`           | info     | Compiler pragma not pinned to a single version (`^`, `>=`, ...)       |
| `missing-zero-address-check`| warning  | Address parameters used without an `address(0)` guard                 |
| `unbounded-loop`            | warning  | Loop bounds depending on storage rather than literals (gas-limit DoS) |
| `selfdestruct-usage`        | critical | `selfdestruct` — deprecation and removal risk (EIP-4758 / EIP-6780)   |
| `hardcoded-address`         | warning  | 40-hex address literals outside named constants                       |
| `timestamp-dependence`      | warning  | `block.timestamp` / `now` used in comparisons (manipulable timing)    |
| `missing-visibility`        | info     | State variables / functions without explicit visibility               |
| `deprecated-keywords`       | warning  | Legacy keywords: `suicide`, `blockhash`                               |
| `assembly-usage`            | info     | Inline assembly bypassing Solidity safety checks                      |

Severity order: `info` < `warning` < `critical`. Full rule descriptions and rationale live in [RULES.md](RULES.md).

## Sample output

This is the real, abridged output of `node soliguard.js examples/VulnerableToken.sol` (the sample is deliberately vulnerable and the run exits with code `1`, as expected):

```text
# SoliGuard report
**SoliGuard v0.1.0** — heuristic Solidity static-analysis security linter.
Generated: 2026-10-15T02:51:29.830Z
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

    pragma solidity ^0.8.17;

[...abridged — see the full report at examples/sample-report.md...]
```

## Installation

The project is not yet published to npm. Use it directly from the repository:

```bash
git clone https://github.com/cybrsecuritesolutions/soliguard.git
cd soliguard
node soliguard.js --help      # no build step, no install step required
```

## Documentation

- [RULES.md](RULES.md) — rule-by-rule reference: what each rule detects, why, with code examples
- [TECHNICAL_SUMMARY.md](TECHNICAL_SUMMARY.md) — architecture, scan pipeline, and design decisions
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to add a new rule and contribute
- [CHANGELOG.md](CHANGELOG.md) — version history
- [SECURITY.md](SECURITY.md) — responsible disclosure and known limitations

## Honesty notice

SoliGuard is heuristic by design and documented as a **pre-audit screening tool** — never a substitute for a professional audit. It is a pattern matcher, not a verifier: it can miss real vulnerabilities (especially logic bugs) and it can flag code that is perfectly safe. Every finding must be reviewed by a human. The project makes no claim of audit-grade coverage.

## License

[MIT](LICENSE) © 2026 SoliGuard contributors