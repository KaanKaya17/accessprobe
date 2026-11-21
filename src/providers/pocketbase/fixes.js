// PocketBase API rule strings for findings, plus how reports/prompts present them.

export const fixStyle = {
  lang: 'js',
  codeLabel: 'Fix (PocketBase API rules — Dashboard → Collections → ⚙ → API Rules, or a pb_migrations file)',
  fixWhere: 'Please fix this in the PocketBase collection API rules, not in the frontend.',
  codeIntro: 'Set these API rules (adjust field names if needed), in the dashboard or as a new pb_migrations file:',
  dont: 'Do not set a rule to "" (public) or to just @request.auth.id != "" for user data, and never ship superuser credentials to the client. Afterwards show me all five API rules of this collection so I can review them.',
  secretMove: 'Move every call that needs this secret into a server route or a pb_hooks handler.',
};

const LABEL = { listRule: 'List/Search rule', viewRule: 'View rule', createRule: 'Create rule', updateRule: 'Update rule', deleteRule: 'Delete rule' };

// owner = the field holding the owner's user id ("id" for the users collection itself)
export function ownerRules(owner) {
  const o = owner || 'user';
  if (o === 'id') {
    return {
      listRule: 'id = @request.auth.id',
      viewRule: 'id = @request.auth.id',
      updateRule: 'id = @request.auth.id',
      deleteRule: 'id = @request.auth.id',
    };
  }
  return {
    listRule: `${o} = @request.auth.id`,
    viewRule: `${o} = @request.auth.id`,
    createRule: `@request.auth.id != "" && @request.body.${o} = @request.auth.id`,
    updateRule: `${o} = @request.auth.id && (@request.body.${o}:isset = false || @request.body.${o} = @request.auth.id)`,
    deleteRule: `${o} = @request.auth.id`,
  };
}

const jsString = (s) => `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

// rules: { listRule: "…", … } → dashboard lines + an equivalent migration
export function rulesCode(collection, rules, { comment = [] } = {}) {
  const names = Object.keys(rules);
  const pad = Math.max(...names.map((n) => LABEL[n].length));
  return [
    `// "${collection}" → API Rules`,
    ...comment.map((c) => `// ${c}`),
    ...names.map((n) => `//   ${`${LABEL[n]}:`.padEnd(pad + 1)}  ${rules[n]}`),
    '',
    `// as a migration, e.g. pb_migrations/<unix time>_fix_${collection}_rules.js:`,
    'migrate((app) => {',
    `  const c = app.findCollectionByNameOrId(${jsString(collection)});`,
    ...names.map((n) => `  c.${n} = ${jsString(rules[n])};`),
    '  app.save(c);',
    '});',
  ].join('\n');
}

export function ownerFix(collection, owner, which) {
  const all = ownerRules(owner);
  const picked = Object.fromEntries(which.filter((w) => w in all).map((w) => [w, all[w]]));
  const comment = owner ? [] : ['accessprobe could not find the owner field; add a relation field "user" → users and adjust the name'];
  return rulesCode(collection, Object.keys(picked).length ? picked : all, { comment });
}

export function noOwnerFix(collection) {
  return rulesCode(collection, ownerRules('user'), {
    comment: ['no owner field found: add a relation field "user" (→ users, max 1, required), then:'],
  });
}

// Users may keep editing their own record, but not the fields that grant rights.
export function privilegeFix(collection, owner, fields, current = {}) {
  const lock = fields.map((f) => `@request.body.${f}:isset = false`).join(' && ');
  const base = current.updateRule && /@request\.auth\.id/.test(current.updateRule) ? `(${current.updateRule})` : `${owner || 'id'} = @request.auth.id`;
  const rules = { updateRule: `${base} && ${lock}` };
  if (owner === 'id') {
    // sign-up goes through the create rule: block the fields there too
    rules.createRule = current.createRule ? `(${current.createRule}) && ${lock}` : lock;
  }
  return rulesCode(collection, rules, {
    comment: [`set ${fields.join(', ')} only from trusted code (a pb_hooks handler, a payment webhook, or the dashboard)`],
  });
}
