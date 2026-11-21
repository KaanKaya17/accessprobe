import { aiPrompt, styleFor, fixCode } from './prompt.js';

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const color = {
  red: c('31'),
  yellow: c('33'),
  green: c('32'),
  cyan: c('36'),
  dim: c('2'),
  bold: c('1'),
};

const SEV = {
  critical: { icon: '✖', paint: color.red, label: 'CRITICAL' },
  warning: { icon: '!', paint: color.yellow, label: 'WARNING' },
  info: { icon: 'i', paint: color.cyan, label: 'INFO' },
};
const ORDER = ['critical', 'warning', 'info'];

// stats are optional; without any tested resource there is nothing to grade
export function grade(findings, stats) {
  const resources = stats && (stats.resources ?? stats.tables);
  if (stats && resources === 0 && !findings.length) return 'N/A';
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const warn = findings.filter((f) => f.severity === 'warning').length;
  if (crit >= 2) return 'F';
  if (crit === 1) return 'D';
  if (warn > 2) return 'C';
  if (warn > 0) return 'B';
  return 'A';
}

const platformsOf = (r) => r.platforms || [{ id: r.platform, label: r.platform, stats: r.stats }];
const multi = (r) => platformsOf(r).length > 1;
const tag = (r, f) => (multi(r) && f.platformLabel ? `[${f.platformLabel}] ` : '');
const sorted = (r) => [...r.findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

function summaryLine(p) {
  const s = p.stats || {};
  const parts = (s.summary || []).map(([n, what]) => `${n} ${what}`).join(', ');
  return `${parts}${s.seconds ? ` in ${s.seconds}s` : ''}`;
}

function coverageLine(p, paint = true) {
  const { resources, resourceLabel = 'resources', fullyTested, readOnly = 0 } = p.stats || {};
  if (!resources || fullyTested === undefined) return '';
  let line = `Coverage: ${fullyTested}/${resources} ${resourceLabel} fully attacked (A wrote a record, B tried to read, change, forge and delete it)`;
  if (readOnly) line += `, ${readOnly} read-only for users`;
  if (!paint) return `${line}.`;
  return fullyTested + readOnly === resources ? color.green(line) : color.yellow(line);
}

export function printReport(r, { wroteFile = false } = {}) {
  const out = [];
  const g = grade(r.findings, r.stats);
  const gp = g === 'A' ? color.green : g === 'B' || g === 'N/A' ? color.yellow : color.red;
  out.push('');
  out.push(color.bold(`accessprobe report — ${r.target}`));
  out.push(`Grade: ${gp(color.bold(g))}   ${counts(r.findings)}`);
  for (const p of platformsOf(r)) {
    const prefix = multi(r) ? `${p.label}: ` : '';
    out.push(color.dim(prefix + summaryLine(p)));
    const cov = coverageLine(p);
    if (cov) out.push(prefix + cov);
  }
  if (g === 'N/A') out.push(color.yellow(color.bold('Nothing was tested — this is NOT a clean bill of health. See Notes.')));
  out.push('');

  for (const f of sorted(r)) {
    const s = SEV[f.severity];
    out.push(`${s.paint(`${s.icon} ${s.label}`)}  ${color.bold(tag(r, f) + f.title)}`);
    out.push(`   ${f.detail}`);
    out.push(color.dim(`   proof: ${f.evidence}`));
    out.push('');
  }

  if (r.passed.length) {
    out.push(color.green(color.bold('Passed')));
    for (const p of r.passed) out.push(color.green(`  ✔ ${p}`));
    out.push('');
  }
  if (r.notes.length) {
    out.push(color.bold('Notes'));
    for (const n of r.notes) out.push(`  • ${n}`);
    out.push('');
  }
  if (!wroteFile && r.findings.some((f) => f.fix)) {
    out.push(color.dim('Fixes and copy-paste AI prompts for each finding: run with --out report.md'));
  }
  console.log(out.join('\n'));
}

export function markdownReport(r) {
  const g = grade(r.findings, r.stats);
  const md = [];
  md.push('# accessprobe report');
  md.push('');
  md.push(`**Target:** ${r.target}  `);
  md.push(`**Date:** ${r.date}  `);
  md.push(`**Grade:** ${g} — ${counts(r.findings)}`);
  md.push('');
  for (const p of platformsOf(r)) {
    md.push(`**${p.label}:** tested ${summaryLine(p)} with two real test users (A and B).  `);
    const cov = coverageLine(p, false);
    if (cov) md.push(`${cov}  `);
  }
  if (g === 'N/A') md.push('', '> ⚠️ **Nothing was tested — this is not a clean bill of health.** See Notes.');
  md.push('');
  md.push('Every critical finding below was **proven** with a real request against data the test users created themselves.');
  md.push('');

  sorted(r).forEach((f, i) => {
    const style = styleFor(f, r.fixStyles);
    md.push(`## ${i + 1}. [${f.severity.toUpperCase()}] ${tag(r, f)}${f.title}`);
    md.push('');
    md.push(f.detail);
    md.push('');
    md.push(`**Proof:** \`${f.evidence.replace(/`/g, "'")}\``);
    md.push('');
    const code = fixCode(f);
    if (code) {
      md.push(`**${style.codeLabel}:**`);
      md.push('');
      md.push('```' + style.lang);
      md.push(code);
      md.push('```');
      md.push('');
    }
    if (f.fix?.steps?.length) {
      md.push('**Fix:**');
      md.push('');
      f.fix.steps.forEach((s) => md.push(`- ${s}`));
      md.push('');
    }
    if (f.severity !== 'info') {
      md.push('<details><summary>Prompt for Lovable / Bolt / Cursor / Claude Code</summary>');
      md.push('');
      md.push('```text');
      md.push(aiPrompt(f, style, f.platformLabel || 'my'));
      md.push('```');
      md.push('');
      md.push('</details>');
      md.push('');
    }
  });

  if (r.passed.length) {
    md.push('## Passed checks');
    md.push('');
    r.passed.forEach((p) => md.push(`- ✔ ${p}`));
    md.push('');
  }
  if (r.notes.length) {
    md.push('## Notes');
    md.push('');
    r.notes.forEach((n) => md.push(`- ${n}`));
    md.push('');
  }
  md.push('---');
  md.push('Generated by [accessprobe](https://github.com/KaanKaya17/accessprobe) — only test apps you own.');
  return md.join('\n');
}

function counts(findings) {
  const n = (s) => findings.filter((f) => f.severity === s).length;
  return `${n('critical')} critical, ${n('warning')} warnings, ${n('info')} info`;
}
