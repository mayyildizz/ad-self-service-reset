// The only module that speaks LDAP. Everything here is scoped to AD_BASE_DN.
//
// Why LDAPS is mandatory: a domain controller refuses to write `unicodePwd`
// over a cleartext connection, so port 389 can search but never reset.
//
// Two safety rules, both enforced here so every caller inherits them:
//   1. A lookup that does not return EXACTLY ONE account is a failure.
//   2. Protected accounts (adminCount=1, member of a protected group, or in a
//      protected OU) are never reset through this path. Those go through IT.
import { Client, Attribute, Change } from 'ldapts';
import { randomInt } from 'node:crypto';
import cfg from './config.js';

const UAC_DISABLED = 0x2;
const ATTRS = ['dn', 'cn', 'sAMAccountName', 'userPrincipalName', 'displayName', 'mail',
  'userAccountControl', 'adminCount', 'memberOf', 'lockoutTime', 'pwdLastSet', cfg.ad.recoveryMailAttr];

/**
 * A password the person can read off a phone and type into a Windows login
 * box: no O/0, l/1/I, and always one of each class so it clears the default
 * domain complexity policy. Generated with a CSPRNG and a proper shuffle.
 */
export function generatePassword(len = cfg.passwordLength) {
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digit = '23456789';
  const special = '!@#$%';
  const all = lower + upper + digit + special;
  const pick = (s) => s[randomInt(0, s.length)];
  const chars = [pick(lower), pick(upper), pick(digit), pick(special)];
  while (chars.length < len) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

/** AD wants the new password quoted and UTF-16LE encoded. */
const encodePassword = (plain) => Buffer.from(`"${plain}"`, 'utf16le');

const escapeFilter = (s) =>
  String(s).replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));

function tlsOptions() {
  const o = { rejectUnauthorized: cfg.ad.rejectUnauthorized };
  if (cfg.ad.caCert) o.ca = [cfg.ad.caCert];
  // SNI: some DCs only present the right certificate when the hostname is sent.
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(cfg.ad.host)) o.servername = cfg.ad.host;
  return o;
}

export async function withClient(fn) {
  const client = new Client({
    url: `ldaps://${cfg.ad.host}:${cfg.ad.port}`,
    tlsOptions: tlsOptions(),
    timeout: cfg.ad.timeoutMs,
    connectTimeout: cfg.ad.timeoutMs,
  });
  try {
    await client.bind(cfg.ad.bindDN, cfg.ad.bindPassword);
    return await fn(client);
  } finally {
    try { await client.unbind(); } catch { /* socket already closed */ }
  }
}

const cnOf = (dn) => (String(dn).match(/^CN=([^,]+)/i)?.[1] || '').replace(/\\,/g, ',').toLowerCase();

function classify(e) {
  const memberOf = [].concat(e.memberOf || []).map(String);
  const user = {
    dn: e.dn,
    cn: String(e.cn || ''),
    sam: String(e.sAMAccountName || ''),
    upn: String(e.userPrincipalName || ''),
    displayName: String(e.displayName || e.cn || ''),
    mail: String(e.mail || ''),
    recoveryMail: String([].concat(e[cfg.ad.recoveryMailAttr] || [])[0] || ''),
    uac: Number(e.userAccountControl || 0),
    adminCount: Number(e.adminCount || 0),
    lockedOut: String(e.lockoutTime || '0') !== '0',
    memberOf,
  };
  const reasons = [];
  if (user.adminCount === 1) reasons.push('adminCount=1');
  if (cfg.ad.protectedDnRegex && cfg.ad.protectedDnRegex.test(user.dn)) reasons.push('protected OU');
  const hit = memberOf.map(cnOf).find((cn) => cfg.ad.protectedGroups.includes(cn));
  if (hit) reasons.push(`member of ${hit}`);
  if (reasons.length) return { status: 'protected', user, why: reasons.join(', ') };
  if (user.uac & UAC_DISABLED) return { status: 'disabled', user };
  return { status: 'ok', user };
}

/**
 * Look one account up by sAMAccountName or UPN, inside AD_BASE_DN only.
 * → { status: 'ok'|'protected'|'disabled', user } | { status: 'not_found'|'ambiguous' }
 */
export async function findUser(loginRaw) {
  const login = String(loginRaw || '').trim();
  if (!/^[A-Za-z0-9._$@-]{1,128}$/.test(login)) return { status: 'not_found' };
  const v = escapeFilter(login);
  const filter = login.includes('@')
    ? `(&(objectCategory=person)(objectClass=user)(|(userPrincipalName=${v})(sAMAccountName=${v})))`
    : `(&(objectCategory=person)(objectClass=user)(sAMAccountName=${v}))`;

  const entries = await withClient(async (client) => {
    const { searchEntries } = await client.search(cfg.ad.baseDN, {
      scope: 'sub', filter, attributes: ATTRS, sizeLimit: 5,
    });
    return searchEntries;
  });
  if (entries.length !== 1) return { status: entries.length ? 'ambiguous' : 'not_found' };
  return classify(entries[0]);
}

/**
 * Set a new password on a DN and clear the lockout. Two separate modifies,
 * never merged: AD rejects a single modify carrying both unicodePwd and
 * lockoutTime. The unlock is best-effort; a changed password with a stale
 * lockout ages out on its own, so it must not mask a successful reset.
 */
export async function resetPassword(dn, plain) {
  if (cfg.dryRun) return { ok: true, unlocked: true, dryRun: true };
  return withClient(async (client) => {
    await client.modify(dn, new Change({
      operation: 'replace',
      modification: new Attribute({ type: 'unicodePwd', values: [encodePassword(plain)] }),
    }));
    let unlocked = true;
    try {
      await client.modify(dn, new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'lockoutTime', values: ['0'] }),
      }));
    } catch { unlocked = false; }
    if (cfg.ad.mustChangeAtLogon) {
      try {
        await client.modify(dn, new Change({
          operation: 'replace',
          modification: new Attribute({ type: 'pwdLastSet', values: ['0'] }),
        }));
      } catch { /* optional */ }
    }
    return { ok: true, unlocked };
  });
}

/** Bind-only reachability probe. */
export async function adHealth() {
  try {
    await withClient(async () => true);
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
}
