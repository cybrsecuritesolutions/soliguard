# Changelog

All notable changes to SoliGuard are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-15

### Added

- **SoliGuard v0.1.0** — a lightweight, zero-dependency, heuristic Solidity static-analysis security linter for Node.js >= 18.
- **11 heuristic rules**, each with severity, description, and actionable per-finding messages:

  | Rule | Severity |
  | --- | --- |
  | `avoid-tx-origin` | warning |
  | `unsafe-low-level-calls` | warning |
  | `floating-pragma` | info |
  | `missing-zero-address-check` | warning |
  | `unbounded-loop` | warning |
  | `selfdestruct-usage` | critical |
  | `hardcoded-address` | warning |
  | `timestamp-dependence` | warning |
  | `missing-visibility` | info |
  | `deprecated-keywords` | warning |
  | `assembly-usage` | info |

- **CLI** — run on a file or directory (recursive), `--json` machine-readable output, `--min-severity` filtering, `--rules`, `--version`, and `--help`.
- **Predictable exit codes** — `0` clean, `1` findings, `2` usage/input error — designed for CI pipelines.
- **Test suite** — Node's built-in test runner (`node:test`, zero deps): one fixture per rule, JSON output shape, exit-code contract, severity filtering, and recursive directory scanning.
- **CI** — GitHub Actions workflow running the suite and a smoke run on the sample contract on Node 18/20/22.
- **Documentation** — README, rule reference (`RULES.md`), architecture notes (`TECHNICAL_SUMMARY.md`), contributing guide, security policy, and this changelog.
- **Sample deliverables** — `examples/VulnerableToken.sol` (deliberately vulnerable, all rules represented) with sample reports in Markdown and JSON.

### Notes

- Heuristic by design: the tool is a pre-audit screening aid, **not** a substitute for a professional security audit.
- Project not yet published to npm; the public repository URL is still being finalized.