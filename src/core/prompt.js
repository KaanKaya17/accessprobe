// Copy-paste prompt for AI app builders (Lovable, Bolt, Cursor, Claude Code).
// Platform-specific wording comes from the adapter's fixStyle.

const GENERIC = {
  lang: 'text',
  codeLabel: 'Fix',
  fixWhere: 'Please fix this on the backend (security rules / permissions), not in the frontend.',
  codeIntro: 'Apply this change (adjust names if needed):',
  dont: 'Do not loosen any other rule. Afterwards list every rule that applies here so I can review it.',
  secretMove: 'Move every call that needs this secret into a serverless function or server route.',
};

export function styleFor(finding, styles = {}) {
  return { ...GENERIC, ...(styles[finding.platform] || {}) };
}

export function fixCode(finding) {
  return finding.fix?.code ?? finding.fix?.sql ?? null;
}

export function aiPrompt(finding, style = GENERIC, platformLabel = 'my') {
  const leaked = finding.id.startsWith('leaked-');
  const parts = [
    `Security issue found by accessprobe in ${platformLabel === 'my' ? 'my' : `my ${platformLabel}`} app: ${finding.title}.`,
    `Proof: ${finding.evidence}`,
    leaked
      ? 'Please remove this secret from all client-side code and environment variables that are exposed to the browser.'
      : style.fixWhere,
  ];
  const code = fixCode(finding);
  if (code) parts.push(`${style.codeIntro}\n\n${code}`);
  if (finding.fix?.steps?.length) parts.push(`Steps:\n- ${finding.fix.steps.join('\n- ')}`);
  parts.push(leaked ? `${style.secretMove} Afterwards show me where the key is still referenced.` : style.dont);
  return parts.join('\n\n');
}
