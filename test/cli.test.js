'use strict';

/**
 * CLI behaviour tests: exit codes, JSON output shape, --min-severity
 * filtering, and directory scanning.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { run, jsonReport } = require('./helpers');

const FIXTURES = path.join(__dirname, 'fixtures');
const CLEAN = path.join(FIXTURES, 'clean.sol');
const VULN = path.join(__dirname, '..', 'examples', 'VulnerableToken.sol');

test('exit code 0 on a clean contract', () => {
  const r = run([CLEAN]);
  assert.strictEqual(r.status, 0);
  assert.ok(r.stdout.includes('No findings'), 'clean report should say so');
});

test('exit code 1 when findings exist', () => {
  const r = run([VULN]);
  assert.strictEqual(r.status, 1);
  assert.ok(r.stdout.includes('FAIL'), 'text report should show FAIL');
});

test('exit code 2 on usage errors', () => {
  assert.strictEqual(run(['--nope', CLEAN]).status, 2, 'unknown flag');
  assert.strictEqual(run(['does-not-exist.sol']).status, 2, 'missing path');
  assert.strictEqual(
    run(['--min-severity', 'bogus', CLEAN]).status,
    2,
    'invalid severity'
  );
  assert.strictEqual(run([]).status, 2, 'no arguments');
});

test('JSON output parses and contains the expected keys', () => {
  const { status, report } = jsonReport(['--json', VULN]);
  assert.strictEqual(status, 1);
  assert.strictEqual(report.tool, 'soliguard');
  assert.strictEqual(typeof report.version, 'string');
  assert.ok(!Number.isNaN(Date.parse(report.generatedAt)));
  assert.ok(report.honestyNotice.length > 20);
  assert.strictEqual(report.minSeverity, 'info');

  const s = report.summary;
  assert.strictEqual(s.filesScanned, 1);
  assert.ok(Number.isInteger(s.totalFindings) && s.totalFindings > 0);
  for (const sev of ['info', 'warning', 'critical']) {
    assert.ok(Number.isInteger(s.bySeverity[sev]), `bySeverity.${sev}`);
  }
  assert.strictEqual(s.exitCode, 1);
  assert.strictEqual(s.result, 'fail');

  assert.ok(Array.isArray(report.files));
  assert.strictEqual(report.files.length, 1);
  const file = report.files[0];
  assert.strictEqual(file.path, VULN);
  assert.ok(Array.isArray(file.findings));
  for (const f of file.findings) {
    assert.strictEqual(typeof f.rule, 'string');
    assert.ok(Number.isInteger(f.line));
    assert.ok(['info', 'warning', 'critical'].includes(f.severity));
    assert.strictEqual(typeof f.message, 'string');
    assert.ok(f.message.length > 10);
  }
});

test('--min-severity filters findings', () => {
  // VulnerableToken.sol: 1 critical / 11 warning / 9 info at the default threshold.
  const { status, report } = jsonReport([
    '--json',
    '--min-severity',
    'critical',
    VULN,
  ]);
  assert.strictEqual(status, 1);
  assert.strictEqual(report.summary.totalFindings, 1);
  assert.strictEqual(report.summary.bySeverity.critical, 1);
  assert.strictEqual(report.summary.bySeverity.warning, 0);
  assert.strictEqual(report.summary.bySeverity.info, 0);
  assert.ok(report.summary.suppressed > 0, 'suppressed count should be > 0');
  assert.ok(
    report.files[0].findings.every((f) => f.severity === 'critical'),
    'only critical findings should remain'
  );
  assert.ok(report.files[0].findings.every((f) => f.rule === 'selfdestruct-usage'));

  // A clean contract stays clean even at the lowest threshold.
  const c = jsonReport(['--json', '--min-severity', 'info', CLEAN]);
  assert.strictEqual(c.status, 0);
  assert.strictEqual(c.report.summary.totalFindings, 0);
});

test('directory scan walks recursively and reports per-file', () => {
  const dir = path.join(FIXTURES, 'dirscan');
  const { status, report } = jsonReport(['--json', dir]);
  assert.strictEqual(status, 1, 'dir with a vulnerable file should exit 1');
  assert.strictEqual(report.summary.filesScanned, 2);
  assert.ok(report.summary.totalFindings >= 1);

  const paths = report.files.map((f) => f.path);
  assert.ok(paths.some((p) => p.includes('alpha.sol')), 'finds alpha.sol');
  assert.ok(
    paths.some((p) => p.includes('nested') && p.includes('beta.sol')),
    'finds nested/beta.sol (recursion)'
  );

  const beta = report.files.find((f) => f.path.includes('beta.sol'));
  assert.strictEqual(beta.findings.length, 0, 'clean file inside dir has no findings');
});

test('--version and --help exit 0', () => {
  const v = run(['--version']);
  assert.strictEqual(v.status, 0);
  assert.match(v.stdout, /0\.1\.0/);

  const h = run(['--help']);
  assert.strictEqual(h.status, 0);
  assert.ok(h.stdout.includes('Usage'));
});