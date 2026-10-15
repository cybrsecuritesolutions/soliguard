#!/usr/bin/env node
'use strict';

/**
 * SoliGuard v0.1.0
 * A lightweight, dependency-free, heuristic Solidity static-analysis security
 * linter. Runs with plain Node.js >= 18. No runtime dependencies.
 *
 * Usage:
 *   node soliguard.js <file.sol | dir> [--json] [--min-severity info|warning|critical]
 *
 * Options:
 *   --json                     emit a machine-readable JSON report
 *   --min-severity <level>     only report findings at or above this level
 *                              (info | warning | critical, default: info)
 *   --rules                    list the implemented rules and exit
 *   --version / -v             print version and exit
 *   --help / -h                print this help and exit
 *
 * Exit codes:
 *   0  scan completed, no findings at or above the severity threshold
 *   1  scan completed, findings exist at or above the threshold
 *   2  usage or input error (bad flag, missing path, unreadable file)
 */

const fs = require('fs');
const path = require('path');

const VERSION = '0.1.0';

const HONESTY_NOTICE =
  'SoliGuard is a heuristic pre-audit screening tool and is NOT a substitute for a professional security audit.';

const SEV_ORDER = ['info', 'warning', 'critical'];
const SEV_RANK = { info: 1, warning: 2, critical: 3 };

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/** Remove // comments and string literals (for structural analysis only). */
function stripLine(s) {
  let out = s.replace(/\/\/.*$/, '');
  out = out.replace(/"(?:[^"\\\n]|\\.)*"/g, '""');
  out = out.replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
  return out;
}

/** Net brace delta of a line ({ = +1, } = -1), comments/strings stripped. */
function netBraces(s) {
  let n = 0;
  for (const ch of stripLine(s)) {
    if (ch === '{') n += 1;
    else if (ch === '}') n -= 1;
  }
  return n;
}

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

/**
 * Every rule is { id, severity, title, description, check(lines) }.
 * check() returns an array of findings:
 *   { line, snippet, message, severity? }   (severity overrides rule severity)
 */

const RULES = [
  {
    id: 'avoid-tx-origin',
    severity: 'warning',
    title: 'tx.origin used as an authorization signal',
    description:
      'Detects usage of tx.origin, which is the EOA that originated the entire transaction, not the immediate caller.',
    check(lines) {
      const out = [];
      lines.forEach((ln, i) => {
        if (/\btx\.origin\b/.test(ln)) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            message:
              'tx.origin is used. tx.origin is the account that originated the whole transaction, so a contract phished by that account can pass tx.origin checks the user never intended. For authorization, use msg.sender (the immediate caller) instead.',
          });
        }
      });
      return out;
    },
  },

  {
    id: 'unsafe-low-level-calls',
    severity: 'warning',
    title: 'Low-level or poorly-guarded external calls',
    description:
      'Detects .call / .delegatecall / .send / .transfer invocations, which do not automatically revert on failure and are common reentrancy vectors.',
    check(lines) {
      const out = [];
      const re = /\b\.(call|delegatecall|send|transfer)\s*(?:\(|\{)/;
      lines.forEach((ln, i) => {
        const m = ln.match(re);
        if (!m) return;
        out.push({
          line: i + 1,
          snippet: ln.trim(),
          message:
            `.${m[1]}() used. .transfer()/.send() forward only 2300 gas and return a bool instead of reverting; .call()/.delegatecall() are raw low-level calls that also return a bool. Verify the returned value, avoid state changes after the call (checks-effects-interactions), and consider a reentrancy guard. Note: this heuristic can also match high-level ERC20 .transfer(.` +
            ') calls, which are usually fine — review each hit.',
        });
      });
      return out;
    },
  },

  {
    id: 'floating-pragma',
    severity: 'info',
    title: 'Floating compiler pragma',
    description:
      'Detects pragma solidity constraints like ^0.8.x or >=0.8.0 <0.9.0 that do not pin a single compiler version.',
    check(lines) {
      const out = [];
      lines.forEach((ln, i) => {
        const m = ln.match(/^\s*pragma\s+solidity\s+(\^|>=|>|<=|<)/);
        if (m) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            message:
              `Floating pragma constraint ("${m[1]}..."). The contract is not pinned to one compiler version, so identical source can compile to different bytecode across versions, making audits and reproducible builds unreliable. Pin an exact version (e.g. "pragma solidity 0.8.24;").`,
          });
        }
      });
      return out;
    },
  },

  {
    id: 'missing-zero-address-check',
    severity: 'warning',
    title: 'Address parameter used without zero-address validation',
    description:
      'Scans constructor/external/public functions with address parameters and checks whether an address(0) guard is visible in the function body.',
    check(lines) {
      const out = [];
      // Locate function-like declarations with their bodies (heuristic brace matching).
      const ctorRe = /^\s*constructor\s*\(([^)]*)\)/;
      const fnRe = /^\s*function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/;
      for (let i = 0; i < lines.length; i++) {
        const ln = stripLine(lines[i]);
        const mc = ln.match(ctorRe);
        const mf = mc ? null : ln.match(fnRe);
        if (!mc && !mf) continue;
        const isCtor = !!mc;
        const paramsRaw = mc ? mc[1] : mf[2];
        // Find '{' opening the body (signature may span several lines).
        let bStart = -1;
        for (let j = i; j < Math.min(lines.length, i + 30); j++) {
          if (stripLine(lines[j]).includes('{')) { bStart = j; break; }
        }
        if (bStart === -1) continue;
        const sigBlock = lines.slice(i, bStart + 1).join('\n');
        // Match the closing brace.
        let depth = 0;
        let bodyEnd = -1;
        for (let j = bStart; j < lines.length; j++) {
          depth += netBraces(lines[j]);
          if (depth === 0) { bodyEnd = j; break; }
        }
        if (bodyEnd === -1) continue;
        const body = lines.slice(bStart + 1, bodyEnd).join('\n');
        const bodyClean = lines.slice(bStart + 1, bodyEnd).map(stripLine).join('\n');
        // Only flag entry points (callable by anyone), not internal/private
        // helpers.
        const vis = sigBlock.match(/\b(public|private|internal|external)\b/);
        const visStr = vis ? vis[1] : null;
        const eligible = isCtor || visStr === 'public' || visStr === 'external' || visStr === null;
        if (!eligible) continue;
        // view/pure functions are not write paths; skip them to avoid noise.
        if (/\b(view|pure)\b/.test(sigBlock)) continue;
        const hasZero = /address\s*\(\s*0\s*\)/.test(bodyClean);
        const pre = /\baddress(?:\s+payable)?\s+([A-Za-z_$][\w$]*)/g;
        let pm;
        while ((pm = pre.exec(paramsRaw))) {
          const p = pm[1];
          if (hasZero) continue;
          if (!new RegExp('\\b' + p + '\\b').test(bodyClean)) continue; // unused param
          out.push({
            line: i + 1,
            snippet: lines[i].trim(),
            message:
              `Address parameter "${p}" is used but no address(0) check is visible in the function body. ` +
              `Address(0) can permanently lock funds or bypass access control. Consider require(${p} != address(0), "...") as the first statement of the function.`,
          });
        }
      }
      return out;
    },
  },

  {
    id: 'unbounded-loop',
    severity: 'warning',
    title: 'Loop bound is not a fixed literal/constant',
    description:
      'Detects for-loops whose condition does not reference a literal or constant, i.e. loops that are not provably bounded.',
    check(lines) {
      const out = [];
      const re = /for\s*\(([^;]*);\s*([^;]+);\s*([^)]*)\)/;
      lines.forEach((ln, i) => {
        const m = ln.match(re);
        if (!m) return;
        const cond = m[2].trim();
        if (/\d/.test(cond)) return; // bounded by a literal
        out.push({
          line: i + 1,
          snippet: ln.trim(),
          message:
            `Loop condition "${cond}" does not reference a fixed literal or constant, so the loop is not provably bounded. ` +
            'If the bound depends on storage (e.g. a dynamic array length), the loop is unbounded: one transaction can exceed the block gas limit and permanently lock funds/state (DoS). Use a fixed bound or explicit pagination (cursor/chunking).',
        });
      });
      return out;
    },
  },

  {
    id: 'selfdestruct-usage',
    severity: 'critical',
    title: 'selfdestruct / contract destruction',
    description:
      'Detects selfdestruct, which can delete contract bytecode and force-send its balance, and whose semantics keep changing across EVM upgrades.',
    check(lines) {
      const out = [];
      lines.forEach((ln, i) => {
        if (/\bselfdestruct\s*\(/.test(ln)) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            message:
              'selfdestruct can delete the contract bytecode and force-send its balance to an address. It is deprecated: EIP-4758 planned its removal and EIP-6780 (Cancun) already restricts its effects, so relying on its semantics is fragile. Remove it unless contract destruction is an explicit, reviewed design goal.',
          });
        }
      });
      return out;
    },
  },

  {
    id: 'hardcoded-address',
    severity: 'warning',
    title: 'Hardcoded address outside a named constant',
    description:
      'Detects 40-hex address literals in the source that are not part of a constant declaration.',
    check(lines) {
      const out = [];
      const re = /0x[0-9a-fA-F]{40}\b/;
      lines.forEach((ln, i) => {
        const m = ln.match(re);
        if (!m) return;
        if (/\bconstant\b/.test(ln)) return;
        out.push({
          line: i + 1,
          snippet: ln.trim(),
          message:
            `Hardcoded address ${m[0]} found outside a named constant. If it participates in ownership/access control, the address is baked into the bytecode and every deployment instance is coupled to it — mistakes are costly and hard to audit across instances. Prefer a constructor parameter (with zero-address validation) or an explicitly documented named constant.`,
        });
      });
      return out;
    },
  },

  {
    id: 'timestamp-dependence',
    severity: 'warning',
    title: 'block.timestamp / now used in a comparison',
    description:
      'Detects block.timestamp or now used together with comparison operators — a common sign of manipulable timing logic.',
    check(lines) {
      const out = [];
      const re = /\b(block\.timestamp|now)\b/;
      lines.forEach((ln, i) => {
        if (!re.test(ln)) return;
        if (!/(?:===|==|!=|<=|>=|[<>])/.test(ln)) return;
        out.push({
          line: i + 1,
          snippet: ln.trim(),
          message:
            'block.timestamp/now is used in a comparison. Timestamps are set by validators within a tolerance window, so strict equality or ordering logic can be influenced and behaves differently across chains. Do not rely on timestamps for randomness, prize/lottery logic, or security-critical ordering.',
        });
      });
      return out;
    },
  },

  {
    id: 'missing-visibility',
    severity: 'info',
    title: 'Missing explicit visibility',
    description:
      'Detects state variables and functions declared without an explicit public/private/internal/external visibility.',
    check(lines) {
      const out = [];
      // --- state variables at contract scope (brace depth 1) ---
      let depth = 0;
      for (let i = 0; i < lines.length; i++) {
        const s = stripLine(lines[i]).trim();
        if (depth === 1 && isStateVarLine(s)) {
          const name = stateVarName(s);
          out.push({
            line: i + 1,
            snippet: s,
            message:
              `State variable "${name}" has no explicit visibility (Solidity silently defaults to "internal"). ` +
              'Declare public/private/internal explicitly so accidental exposure (or accidental hiding) is impossible.',
          });
        }
        depth += netBraces(lines[i]);
      }
      // --- functions ---
      const fnRe = /^\s*function\s+([A-Za-z_$][\w$]*)\s*\(/;
      for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(fnRe);
        if (!m) continue;
        let j = i;
        let block = '';
        while (j < lines.length && j < i + 30) {
          block += lines[j] + ' ';
          if (stripLine(lines[j]).includes('{')) break;
          j += 1;
        }
        if (/\b(public|private|internal|external)\b/.test(block)) continue;
        out.push({
          line: i + 1,
          snippet: lines[i].trim(),
          message:
            `Function "${m[1]}()" has no explicit visibility (Solidity defaults to "public"). ` +
            'Declare public/private/internal/external explicitly — an accidentally public function is a classic attack surface.',
        });
      }
      return out;
    },
  },

  {
    id: 'deprecated-keywords',
    severity: 'warning',
    title: 'Deprecated or legacy keywords',
    description:
      'Detects legacy keywords that signal dated or risky patterns: the selfdestruct alias "suicide" and "blockhash".',
    check(lines) {
      const out = [];
      lines.forEach((ln, i) => {
        if (/\bsuicide\s*\(/.test(ln)) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            severity: 'info',
            message:
              '"suicide(...)" is the deprecated alias of selfdestruct. Replace it with selfdestruct or, better, remove self-destruction entirely — its semantics have changed across EVM forks (EIP-4758, EIP-6780).',
          });
        }
        if (/\bblockhash\s*\(/.test(ln)) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            severity: 'warning',
            message:
              '"blockhash(...)" is a legacy pattern: it only returns a meaningful value for the last 256 blocks and is weakly influenced by validators — unsafe for randomness/lotteries (EIP-4399 replaced it with prevrandao). Prefer a commit-reveal scheme or a verifiable random function (VRF).',
          });
        }
      });
      return out;
    },
  },

  {
    id: 'assembly-usage',
    severity: 'info',
    title: 'Inline assembly',
    description:
      'Detects inline assembly blocks, which bypass Solidity-level safety checks.',
    check(lines) {
      const out = [];
      lines.forEach((ln, i) => {
        if (/\bassembly\s*\{/.test(ln)) {
          out.push({
            line: i + 1,
            snippet: ln.trim(),
            message:
              'Inline assembly bypasses Solidity safety checks (bounds, overflow, reentrancy tooling) and is hard to audit. Keep it minimal, comment it as "audited assembly", and prefer plain Solidity where possible.',
          });
        }
      });
      return out;
    },
  },
];

function isStateVarLine(s) {
  if (!/;\s*$/.test(s)) return false;
  if (!/^(mapping\s*\(|uint|int|address|bool|string\b|bytes\d*)/.test(s)) return false;
  if (/\b(public|private|internal|external|immutable|constant)\b/.test(s)) {
    // constant/immutable alone does not replace visibility; but visibility words kill the flag.
    if (/\b(public|private|internal|external)\b/.test(s)) return false;
  }
  return true;
}

function stateVarName(s) {
  let m = s.match(/\)\s*([A-Za-z_$][\w$]*)\s*(?:=|;)/); // mapping ...) name ;
  if (!m) m = s.match(/(?:uint|int|address|bool|string|bytes\d*)\w*\s+([A-Za-z_$][\w$]*)/);
  return m ? m[1] : '?';
}

/* ------------------------------------------------------------------ */
/* Scanning                                                            */
/* ------------------------------------------------------------------ */

function collectFiles(paths) {
  const files = [];
  for (const p of paths) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (e) {
      throw new Error('path not found: ' + p);
    }
    if (st.isFile()) {
      files.push(p);
    } else if (st.isDirectory()) {
      const walk = (dir) => {
        for (const entry of fs.readdirSync(dir)) {
          const full = path.join(dir, entry);
          const s = fs.statSync(full);
          if (s.isDirectory()) walk(full);
          else if (/\.sol$/i.test(entry)) files.push(full);
        }
      };
      walk(p);
    }
  }
  return files;
}

function scanFile(filePath, minSeverity) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/);
  const findings = [];
  for (const rule of RULES) {
    let found;
    try {
      found = rule.check(lines) || [];
    } catch (e) {
      found = []; // a broken rule must not crash the whole scan
    }
    for (const f of found) {
      f.rule = rule.id;
      if (!f.severity) f.severity = rule.severity;
      findings.push(f);
    }
  }
  const suppressed = findings.filter((f) => SEV_RANK[f.severity] < SEV_RANK[minSeverity]).length;
  const visible = findings
    .filter((f) => SEV_RANK[f.severity] >= SEV_RANK[minSeverity])
    .sort((a, b) => a.line - b.line || a.rule.localeCompare(b.rule));
  return { findings: visible, suppressed };
}

function buildReport(files, minSeverity) {
  const fileReports = [];
  let total = 0;
  let suppressed = 0;
  const bySeverity = { info: 0, warning: 0, critical: 0 };
  for (const f of files) {
    const r = scanFile(f, minSeverity);
    suppressed += r.suppressed;
    total += r.findings.length;
    for (const x of r.findings) bySeverity[x.severity] += 1;
    fileReports.push({ path: f, findings: r.findings });
  }
  const exitCode = total > 0 ? 1 : 0;
  return {
    generatedAt: new Date().toISOString(),
    summary: {
      filesScanned: files.length,
      totalFindings: total,
      bySeverity,
      suppressed,
      result: exitCode === 0 ? 'pass' : 'fail',
      exitCode,
    },
    files: fileReports,
  };
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

function formatText(report, minSeverity) {
  const L = [];
  const s = report.summary;
  L.push('# SoliGuard report');
  L.push('');
  L.push(`**SoliGuard v${VERSION}** — heuristic Solidity static-analysis security linter.`);
  L.push('');
  L.push(`Generated: ${report.generatedAt}`);
  L.push('');
  L.push(`> **Honesty notice:** ${HONESTY_NOTICE}`);
  L.push('> Every finding below is a *potential* issue and requires manual review. False positives and false negatives are expected; nothing here replaces a professional audit.');
  L.push('');
  L.push('## Summary');
  L.push('');
  L.push(`- Files scanned: ${s.filesScanned}`);
  L.push(`- Findings (at/above threshold): ${s.totalFindings}`);
  L.push(`  - critical: ${s.bySeverity.critical}, warning: ${s.bySeverity.warning}, info: ${s.bySeverity.info}`);
  if (s.suppressed > 0) {
    L.push(`- Findings suppressed below --min-severity ${minSeverity}: ${s.suppressed}`);
  }
  L.push(`- Severity threshold (--min-severity): ${minSeverity}`);
  L.push(`- Result: **${s.result.toUpperCase()}** (exit code ${s.exitCode})`);
  L.push('');
  for (const fr of report.files) {
    if (fr.findings.length === 0) continue;
    L.push(`## Findings — ${fr.path}`);
    L.push('');
    for (const x of fr.findings) {
      L.push(`### [${x.severity}] ${x.rule} — line ${x.line}`);
      L.push('');
      L.push('```solidity');
      L.push(x.snippet);
      L.push('```');
      L.push('');
      L.push(x.message);
      L.push('');
    }
  }
  if (s.totalFindings === 0) {
    L.push('No findings at or above the severity threshold.');
    L.push('');
  }
  return L.join('\n');
}

function formatJson(report, minSeverity) {
  return JSON.stringify(
    {
      tool: 'soliguard',
      version: VERSION,
      generatedAt: report.generatedAt,
      honestyNotice: HONESTY_NOTICE,
      minSeverity,
      summary: report.summary,
      files: report.files,
    },
    null,
    2
  );
}

function printRules() {
  console.log(`SoliGuard v${VERSION} — implemented rules\n`);
  for (const r of RULES) {
    console.log(`  ${r.id.padEnd(30)} ${r.severity.padEnd(8)} ${r.title}`);
  }
  console.log('\nSeverity order: info < warning < critical');
}

function printHelp() {
  console.log(`SoliGuard v${VERSION} — heuristic Solidity static-analysis security linter (zero dependencies, Node.js >= 18)

Usage:
  node soliguard.js <file.sol | dir> [--json] [--min-severity info|warning|critical]

Options:
  --json                     emit a machine-readable JSON report
  --min-severity <level>     only report findings at or above this level (default: info)
  --rules                    list the implemented rules and exit
  --version / -v             print version and exit
  --help / -h                print this help and exit

Exit codes:
  0  scan completed, no findings at or above the severity threshold
  1  scan completed, findings exist at or above the threshold
  2  usage or input error

${HONESTY_NOTICE}`);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const opts = { json: false, minSeverity: 'info', help: false, version: false, rules: false, paths: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (a === '--rules') opts.rules = true;
    else if (a === '--min-severity') {
      opts.minSeverity = argv[i + 1];
      i += 1;
    } else if (a.startsWith('--min-severity=')) {
      opts.minSeverity = a.split('=')[1];
    } else if (a.startsWith('-') && a !== '-') {
      throw new Error('unknown option: ' + a);
    } else {
      opts.paths.push(a);
    }
  }
  return opts;
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error('soliguard: ' + e.message);
    process.exit(2);
  }
  if (opts.help) { printHelp(); process.exit(0); }
  if (opts.version) { console.log('soliguard v' + VERSION); process.exit(0); }
  if (opts.rules) { printRules(); process.exit(0); }
  if (!SEV_ORDER.includes(opts.minSeverity)) {
    console.error('soliguard: invalid --min-severity "' + opts.minSeverity + '" (expected one of: ' + SEV_ORDER.join(', ') + ')');
    process.exit(2);
  }
  if (opts.paths.length === 0) { printHelp(); process.exit(2); }

  let files;
  try {
    files = collectFiles(opts.paths);
  } catch (e) {
    console.error('soliguard: ' + e.message);
    process.exit(2);
  }
  if (files.length === 0) {
    console.error('soliguard: no .sol files found in the given path(s)');
    process.exit(0);
  }

  const report = buildReport(files, opts.minSeverity);
  if (opts.json) {
    console.log(formatJson(report, opts.minSeverity));
  } else {
    console.log(formatText(report, opts.minSeverity));
  }
  process.exit(report.summary.exitCode);
}

main();