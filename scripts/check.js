#!/usr/bin/env node
// End-to-end verification, run after filling .env:
//
//   npm run check                       config + LDAPS bind + SMTP login
//   npm run check -- --user jsmith      + look that account up and show what the reset would see
//   npm run check -- --mail you@x.com   + send a real test e-mail
//   npm run check -- --user jsmith --reset   REAL reset of that account (asks y/N; honours RESET_DRY_RUN)
import { createInterface } from 'node:readline/promises';
import cfg, { validateConfig } from '../src/config.js';
import { adHealth, findUser, resetPassword, generatePassword } from '../src/ad.js';
import { smtpHealth, sendTest } from '../src/mailer.js';

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const has = (k) => args.includes(k);
const ok = (m) => console.log('  ✔', m);
const warn = (m) => console.log('  ⚠', m);
const bad = (m) => { console.log('  ✘', m); process.exitCode = 1; };

console.log('\n1) Configuration');
const problems = validateConfig();
if (problems.length) { problems.forEach(bad); console.log('\nFix .env and run again.\n'); process.exit(1); }
ok(`AD ${cfg.ad.host}:${cfg.ad.port}, base ${cfg.ad.baseDN}`);
ok(`SMTP ${cfp()}`);
ok(`dry run: ${cfg.dryRun}  |  recovery attribute: ${cfg.ad.recoveryMailAttr}`);
function cfp() { return `${cfg.smtp.host}:${cfg.smtp.port} as ${cfg.smtp.user || '(no auth)'}, from ${cfg.smtp.from}`; }

console.log('\n2) LDAPS bind as service account');
const ad = await adHealth();
if (ad.ok) ok('bind succeeded'); else {
  bad(`bind failed: ${ad.error}`);
  if (/self.signed|certificate|CERT/i.test(ad.error)) console.log('     → The DC certificate is not trusted. Export the CA and set AD_CA_CERT (docs/INSTALL.md §4).');
  if (/ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH/i.test(ad.error)) console.log('     → Nothing listening on 636. Enable LDAPS on the DC (docs/INSTALL.md §3) and check the firewall.');
  if (/invalidCredentials|data 52e/i.test(ad.error)) console.log('     → Wrong AD_BIND_DN / AD_BIND_PASSWORD.');
}

console.log('\n3) SMTP login');
const smtp = await smtpHealth();
if (smtp.ok) ok('SMTP connection + auth succeeded'); else bad(`SMTP failed: ${smtp.error}`);

const user = opt('--user');
let found = null;
if (user && ad.ok) {
  console.log(`\n4) Lookup ${user}`);
  found = await findUser(user);
  if (found.status === 'not_found') bad('not found under AD_BASE_DN (is the account inside that OU?)');
  else if (found.status === 'ambiguous') bad('more than one match: cannot reset safely');
  else {
    const u = found.user;
    ok(`dn: ${u.dn}`);
    ok(`sAMAccountName: ${u.sam}  upn: ${u.upn}`);
    ok(`recovery e-mail (${cfg.ad.recoveryMailAttr}): ${u.recoveryMail || '(EMPTY: this user cannot self-reset)'}`);
    ok(`locked out now: ${u.lockedOut}`);
    if (found.status === 'protected') warn(`PROTECTED (${found.why}) - the page will refuse this account, which is correct. Test with a normal user.`);
    else if (found.status === 'disabled') warn('account is disabled - the page will refuse it');
    else ok('eligible for self-service reset');
  }
}

const mail = opt('--mail');
if (mail && smtp.ok) {
  console.log(`\n5) Send test e-mail to ${mail}`);
  try { await sendTest(mail); ok('sent - check the inbox (and spam)'); } catch (e) { bad(`send failed: ${e.message}`); }
}

if (has('--reset') && found?.status === 'ok') {
  console.log(`\n6) Reset ${found.user.sam}  (RESET_DRY_RUN=${cfg.dryRun})`);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const a = (await rl.question(cfg.dryRun ? '   Dry run: simulate the reset? [y/N] ' : `   This WILL change the password of ${found.user.sam}. Continue? [y/N] `)).trim();
  rl.close();
  if (/^y(es)?$/i.test(a)) {
    const pw = generatePassword();
    try {
      const r = await resetPassword(found.user.dn, pw);
      ok(r.dryRun ? 'dry run: no write performed' : `password changed; unlock ${r.unlocked ? 'ok' : 'FAILED (will age out)'}`);
      if (!r.dryRun) { console.log(`   New password: ${pw}`); console.log('   Verify: log in with it, or run  ldapwhoami -H ldaps://<dc> -D <user@domain> -w <pw>'); }
    } catch (e) {
      bad(`reset failed: ${e.message}`);
      if (/WILL_NOT_PERFORM|0000052D|constraint/i.test(e.message)) console.log('     → Password rejected by policy, or unicodePwd write not allowed (check delegation + LDAPS).');
      if (/insufficient|00002098/i.test(e.message)) console.log('     → Service account lacks "Reset password" on this OU. Re-run deploy/delegate-permissions.ps1.');
    }
  } else ok('skipped');
}

console.log(process.exitCode ? '\nSome checks FAILED.\n' : '\nAll checks passed.\n');
