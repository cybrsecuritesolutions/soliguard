# SoliGuard

**SoliGuard v0.1.0** is a lightweight, dependency-free, heuristic **Solidity static-analysis security linter** — a CLI that scans smart-contract source code for common vulnerability patterns before you even think about an audit.

> ⚠️ **Honesty notice:** SoliGuard is a heuristic pre-audit screening tool and is **NOT a substitute for a professional security audit**. It reports *potential* issues. Every finding requires manual review: false positives and false negatives are expected.

## What it does

SoliGuard reads one `.sol` file (or walks a directory), applies 11 heuristic rules, and produces a report with:

- a stable **rule id** per finding,
- a **severity** (`info` / `warning` / `critical`),
- the offending **line number**,
- a **snippet** of the matched source, and
- a short plain-language explanation of the risk.

It runs on **plain Node.js ≥ 18 with zero runtime dependencies** — there is nothing to install. No npm packages are needed; the linter is a single file that uses only Node's built-ins (`fs`, `path`).

## Quick start

```bash
# clone / download the repo, then just run it:
node soliguard.js path/to/YourContract.sol
node soliguard.js contracts/            # scan a whole directory
node soliguard.js path/to/Contract.sol --json
node soliguard.js path/to/Contract.sol --min-severity warning
```

Try it on the included sample (an intentionally vulnerable token):

```bash
node soliguard.js examples/VulnerableToken.sol
```

The real generated report for that run is committed as [`examples/sample-report.md`](examples/sample-report.md) (and `examples/sample-report.json`).

### Output

- **Default:** a readable Markdown-ish report (`# SoliGuard report`) with a summary, per-finding sections, and the honesty notice in the header.
- **`--json`:** a machine-readable JSON report (`tool`, `version`, `generatedAt`, `honestyNotice`, `summary`, `files[].findings[]`).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings at or above the severity threshold (PASS). |
| `1` | Scan completed; findings exist at or above the threshold (FAIL) — CI-usable. |
| `2` | Usage or input error (bad flag, missing path, invalid `--min-severity`). |

`--min-severity` filters which findings are reported and drives the exit code (default `info`; valid values `info`, `warning`, `critical`).

## Options

```
node soliguard.js <file.sol | dir> [--json] [--min-severity info|warning|critical]

--json                    emit a machine-readable JSON report
--min-severity <level>    only report findings at or above this level (default: info)
--rules                   list the implemented rules and exit
--version / -v            print version and exit
--help / -h               print help and exit
```

## Implemented rules (v0.1)

| Rule id | Severity | Detects |
|---------|----------|---------|
| `avoid-tx-origin` | warning | `tx.origin` used (phishing-prone authorization) |
| `unsafe-low-level-calls` | warning | `.call` / `.delegatecall` / `.send` / `.transfer` usage |
| `floating-pragma` | info | non-pinned pragma (`^`, `>=`, `<`, …) |
| `missing-zero-address-check` | warning | address params used without an `address(0)` guard |
| `unbounded-loop` | warning | `for` loop bound not tied to a fixed literal/constant |
| `selfdestruct-usage` | critical | `selfdestruct` (contract destruction) |
| `hardcoded-address` | warning | raw 40-hex address literal outside a constant |
| `timestamp-dependence` | warning | `block.timestamp` / `now` in a comparison |
| `missing-visibility` | info | state variables / functions without explicit visibility |
| `deprecated-keywords` | info/warning | `suicide` alias (info), `blockhash` (warning) |
| `assembly-usage` | info | inline `assembly { }` blocks |

Details, why-it-matters, and examples for every rule: **[RULES.md](RULES.md)**.

## Limitations (read before trusting output)

- **Heuristic, not exhaustive.** SoliGuard is a pattern scanner, not a data-flow or symbolic analyzer. A clean report does **not** mean the contract is secure.
- **False positives are expected.** For example, `unsafe-low-level-calls` can match high-level ERC-20 `.transfer(...)` calls (usually fine), and `missing-zero-address-check` can miss validation written in a way the heuristic body scan doesn't recognize.
- **False negatives are expected too.** Anything outside the 11 rules — integer overflow/underflow logic, complex reentrancy paths, access-control design flaws, upgradeability issues — is simply not scanned.
- **Multi-line constructs may be missed.** Heuristics are line-oriented: e.g. a `for` loop whose header spans several lines, or a function signature spread over many lines, may not match.
- **`internal`/`private` functions are skipped** by `missing-zero-address-check` by design (validation is expected at the externally-callable entry points).
- **This tool is a pre-audit screening step, not a substitute for a professional security audit.** Treat every finding as a lead to investigate manually.

## License

MIT — see [LICENSE](LICENSE).

## Technical summary

For the curious (and for the grant proposal this project is built around): see [TECHNICAL_SUMMARY.md](TECHNICAL_SUMMARY.md).