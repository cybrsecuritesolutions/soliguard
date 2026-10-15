'use strict';

/**
 * Shared helpers for the SoliGuard test suite (node:test, zero deps).
 */

const { spawnSync } = require('child_process');
const path = require('path');

const SOLIGUARD = path.join(__dirname, '..', 'soliguard.js');
const REPO_ROOT = path.join(__dirname, '..');

/** Run the CLI in a child process; returns { status, stdout, stderr }. */
function run(args) {
  const res = spawnSync(process.execPath, [SOLIGUARD, ...args], {
    encoding: 'utf8',
    cwd: REPO_ROOT,
    timeout: 30000,
  });
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** Run with --json and parse; accepts exit codes 0 or 1 only. */
function jsonReport(args) {
  const r = run(args);
  if (r.status !== 0 && r.status !== 1) {
    throw new Error(
      `expected exit 0 or 1, got ${r.status}\nstderr: ${r.stderr}`
    );
  }
  return { status: r.status, report: JSON.parse(r.stdout) };
}

module.exports = { run, jsonReport, SOLIGUARD };