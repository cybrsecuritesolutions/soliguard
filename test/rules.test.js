'use strict';

/**
 * Rule coverage tests: every implemented rule must fire on its own
 * crafted minimal fixture.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { run, jsonReport } = require('./helpers');

const FIXTURES = path.join(__dirname, 'fixtures');

const RULE_FIXTURES = [
  ['avoid-tx-origin', 'avoid-tx-origin.sol'],
  ['unsafe-low-level-calls', 'unsafe-low-level-calls.sol'],
  ['floating-pragma', 'floating-pragma.sol'],
  ['missing-zero-address-check', 'missing-zero-address-check.sol'],
  ['unbounded-loop', 'unbounded-loop.sol'],
  ['selfdestruct-usage', 'selfdestruct-usage.sol'],
  ['hardcoded-address', 'hardcoded-address.sol'],
  ['timestamp-dependence', 'timestamp-dependence.sol'],
  ['missing-visibility', 'missing-visibility.sol'],
  ['deprecated-keywords', 'deprecated-keywords.sol'],
  ['assembly-usage', 'assembly-usage.sol'],
];

test('each of the 11 rules fires on its crafted fixture', () => {
  for (const [ruleId, file] of RULE_FIXTURES) {
    const { status, report } = jsonReport(['--json', path.join(FIXTURES, file)]);
    assert.strictEqual(status, 1, `${file} should exit 1`);
    const found = new Set(report.files[0].findings.map((f) => f.rule));
    assert.ok(
      found.has(ruleId),
      `${file} should report rule "${ruleId}", got: [${[...found].join(', ')}]`
    );
  }
});

test('--rules lists every implemented rule id', () => {
  const r = run(['--rules']);
  assert.strictEqual(r.status, 0);
  for (const [ruleId] of RULE_FIXTURES) {
    assert.ok(r.stdout.includes(ruleId), `--rules output should mention ${ruleId}`);
  }
});