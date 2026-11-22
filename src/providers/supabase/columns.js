// Sensitive columns in rows someone else could read. A table can be readable on purpose
// (public profiles, a shared board) and still hand out columns nobody meant to publish:
// email, phone, password hashes, API tokens. Reported by column NAME; values are never shown.

const SECRET = [
  /^(password|passwd|pass_hash|password_hash|hashed_password|encrypted_password|pin_hash)$/,
  /^(secret|client_secret|webhook_secret|signing_secret|totp_secret|otp_secret|mfa_secret)$/,
  /^(api_?key|apikey|access_token|refresh_token|auth_token|session_token|id_token|bearer_token|reset_token|reset_password_token|confirmation_token|verification_token|invite_token|magic_link_token)$/,
  /^(private_key|privkey|recovery_codes?|backup_codes?|otp|otp_code)$/,
  /_(secret|password|api_key|apikey|private_key|access_token|refresh_token)$/,
];
const PERSONAL = [
  /^(email|email_address|contact_email|personal_email|billing_email)$/,
  /^(phone|phone_number|mobile|mobile_number|telephone|whatsapp)$/,
  /^(address|street|street_address|address_line[_ ]?\d|home_address|billing_address|shipping_address|postal_code|postcode|zip|zipcode|zip_code)$/,
  /^(date_of_birth|dob|birth_date|birthdate|birthday)$/,
  /^(ssn|social_security_number|national_id|tax_id|vat_number|passport|passport_number|drivers_license|tc_kimlik|tckn)$/,
  /^(iban|bank_account|account_number|routing_number|card_number|card_last4|last4)$/,
  /^(ip|ip_address|last_ip|last_sign_in_ip|signup_ip|user_agent)$/,
  /^(stripe_customer_id|stripe_subscription_id|stripe_account_id|paypal_payer_id|lemon_squeezy_customer_id)$/,
  /^(latitude|longitude|lat|lng|geo|location|home_location)$/,
  /_(email|phone)$/,
];

export function sensitiveColumns(columns) {
  const cols = columns.map(String);
  const secret = cols.filter((c) => SECRET.some((re) => re.test(c.toLowerCase())));
  const personal = cols.filter((c) => !secret.includes(c) && PERSONAL.some((re) => re.test(c.toLowerCase())));
  return { secret, personal };
}

const quote = (c) => (/^[a-z_][a-z0-9_]*$/.test(c) ? c : `"${c.replace(/"/g, '""')}"`);

// who: 'anon' (anyone with the public key) or 'B' (any signed-in user, reading another user's row)
export function sensitiveFinding(table, columns, who, evidence) {
  const { secret, personal } = sensitiveColumns(columns);
  if (!secret.length && !personal.length) return null;
  const all = [...secret, ...personal];
  const reader = who === 'anon' ? 'Anyone (not logged in)' : 'Any signed-in user';
  const keep = columns.filter((c) => !all.includes(c));
  const roles = who === 'anon' ? 'anon, authenticated' : 'authenticated';
  return {
    table,
    id: who === 'anon' ? 'sensitive-columns-anon' : 'sensitive-columns',
    severity: secret.length ? 'critical' : 'warning',
    title: `${reader} can read ${secret.length ? 'secret' : 'personal'} columns of other people's rows in "${table}": ${all.join(', ')}`,
    detail:
      (secret.length
        ? `Secrets (${secret.join(', ')}) must never be readable by other users. `
        : '') +
      (personal.length ? `Personal data (${personal.join(', ')}) is exposed even if the table is meant to be public. ` : '') +
      'RLS works on rows, not columns: a readable row hands out every column in it. Values are not shown in this report.',
    evidence: `${evidence} → row(s) with columns ${all.join(', ')}`,
    fix: {
      sql:
        `-- Option 1: let API roles read only the safe columns (keep RLS for the rows)\n` +
        `revoke select on public.${quote(table)} from ${roles};\n` +
        `grant select (${keep.length ? keep.map(quote).join(', ') : '/* the columns that may be public */'}) on public.${quote(table)} to ${roles};\n` +
        `-- (clients must then select those columns explicitly, not select=*)\n\n` +
        `-- Option 2: move ${all.map(quote).join(', ')} into a separate table readable only by its owner:\n` +
        `-- create table public.${table}_private (… , ${all.map(quote).join(', ')}) + policy using ((select auth.uid()) = user_id)`,
      steps: secret.length ? [`Rotate the exposed ${secret.join(', ')} values: assume they were read.`] : undefined,
    },
  };
}
