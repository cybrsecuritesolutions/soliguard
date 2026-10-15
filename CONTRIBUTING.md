# Contributing to SoliGuard

Thanks for wanting to contribute! SoliGuard is a small, dependency-free project and every rule, test, or doc improvement helps. This guide is intentionally short — read the whole thing before opening a change.

## Ground rules

- **Zero dependencies.** The linter must keep running on plain Node.js >= 18 with no npm install step. Do not add runtime or dev dependencies.
- **Heuristic honesty.** Rules flag *potential* issues. Never describe a rule as a guarantee, and never imply the tool replaces a professional audit.
- **Every rule ships with a test.** No test, no merge.
- **No invented metrics.** If you change behaviour, run the suite and paste the real `npm test` output in your PR description.

## Project layout

```
soliguard.js                 the entire linter (CLI, rules, scanner, report formatters)
package.json                 name, bin, files, scripts (npm test)
test/
  helpers.js                 spawned-CLI helpers (node:test, zero deps)
  rules.test.js              per-rule coverage tests
  cli.test.js                exit codes, JSON shape, filters, directory scans
  fixtures/<rule-id>.sol     one minimal trigger file per rule
  fixtures/clean.sol         negative control (must stay finding-free)
examples/VulnerableToken.sol deliberately vulnerable sample with every rule represented
RULES.md                     rule reference (keep in sync when rules change)
TECHNICAL_SUMMARY.md         architecture notes
```

## How to add a new rule

1. **Create the fixture first** — `test/fixtures/<your-rule-id>.sol`. A minimal, deliberately vulnerable contract that your rule alone should catch. Try to make it trigger *your* rule cleanly; extra findings on the fixture are tolerated but noise is discouraged.
2. **Add the rule** in `soliguard.js`. Every rule is an entry in the exported `RULES` array near the top of the file:

   ```js
   {
     id: 'your-rule-id',        // lowercase-hyphenated, unique
     severity: 'warning',       // info | warning | critical
     title: 'Human-readable title',
     description: 'What it detects and why it matters (used in --rules output).',
     check(lines) {
       // lines: array of source lines (comments/strings removed via stripLine()
       // where structural matching is needed). Return an array of:
       // { line: <1-based line number>, snippet: <trimmed source line>,
       //   message: <actionable explanation> }.
       // A per-finding { severity } overrides the rule severity.
     },
   },
   ```

   Follow the existing style: pattern-match on `stripLine(lines[i])` for structure, prefer line-level matching over brace parsing, and document the rule's false-positive profile in the `message`.
3. **Register the rule in the test map** — add `['your-rule-id', 'your-rule-id.sol']` to `RULE_FIXTURES` in `test/rules.test.js` so the coverage test asserts your fixture fires your rule.
4. **Update the docs** — add the rule row to the table in `README.md` and a full section to `RULES.md` (what it catches, why, example, false positives). Add a `CHANGELOG.md` entry (unreleased section).
5. **Run the suite until it is green**:

   ```bash
   npm test
   ```

   Paste the real output in your PR.

## Style guide

- Two-space indentation, single quotes, semicolons, `'use strict';` (matching the codebase).
- `camelCase` for functions/variables; `kebab-case` for rule ids.
- Every finding message must end with an actionable suggestion and, where relevant, a false-positive note.
- Keep functions small, comment the *why*, and match the existing tone of the docs.

## Asking questions

If you are unsure whether a rule idea fits (or how to wire it in), open an issue with a concrete example contract and what you want to flag — maintainers will reply before you write code.