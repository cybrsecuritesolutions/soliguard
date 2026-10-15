# Security Policy

## What SoliGuard is — and is not

SoliGuard is a **heuristic** static-analysis linter. It pattern-matches common Solidity vulnerability patterns to help developers *screen* code before a professional audit. It is not a verifier:

- It can produce **false positives** (flagging code that is actually safe) — expected and by design.
- It can produce **false negatives** (missing real bugs, especially logic bugs that no pattern can capture) — expected and by design.
- **It is never a substitute for a professional security audit.** Anyone deploying a contract to a live network without an audit does so at their own risk.

Do not rely on a "clean" SoliGuard report as a security guarantee, and do not claim in any document that "SoliGuard says the contract is secure" — the tool cannot make that claim.

## Reporting vulnerabilities

If you find a bug in SoliGuard itself (a rule that crashes on valid input, incorrect output, a false-negative that a heuristic *could* reasonably catch, or a security issue in the tooling), please report it privately.

Until the public repository is published, report to the project maintainers directly:

<!-- TODO: repo URL / security contact once published — replace this block with
     the project's GitHub Security Advisory link (https://github.com/OWNER/REPO/security/advisories/new)
     or the maintainers' preferred contact address. -->

**What to include in a report:**

1. The Solidity snippet or input that triggered the issue.
2. The exact command run and the tool version (`node soliguard.js --version`).
3. (If applicable) what behaviour you expected vs. what happened.

We aim to acknowledge reports within 48 hours and to respond with a fix plan or an explanation within one week.

## Security-relevant behaviour

- The scanner reads files only and never modifies the working tree.
- Finding a vulnerability *in the rule set* (e.g. a rule that never fires on a well-known pattern) is worth reporting — shipping a rule that silently does nothing is a correctness bug we want to fix, not a feature.