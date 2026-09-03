// HTTP layer. Three calls, and the middle one is not optional:
//
//   POST /api/challenge { username }                  → e-mails a code to the recovery address
//   POST /api/reset     { username, challenge_id, code } → resets + returns the new password
//   GET  /api/health                                   → AD bind + SMTP probe (no secrets)
//
// The response to /api/challenge is the same whether the account exists,
// is protected, is disabled, or has no recovery e-mail: "if we found it, a
// code was sent". The real reason is written to the audit log for IT.
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import cfg, { validateConfig } from './config.js';
import { findUser, resetPassword, generatePassword, adHealth } from './ad.js';
import { sendCode, smtpHealth } from './mailer.js';
import { ipAllowed, sendAllowed, mintChallenge, verifyChallenge, maskEmail } from './otp.js';
import { audit, resetsLast24h } from './audit.js';

const problems = validateConfig();
if (problems.length) {
  console.error('Configuration problems:\n - ' + problems.join('\n - '));
  process.exit(1);
}

const app = Fastify({ logger: { level: 'info' }, trustProxy: cfg.trustProxy });
const here = dirname(fileURLToPath(import.meta.url));
app.register(fastifyStatic, { root: join(here, '..', 'public') });

app.addHook('onSend', async (req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Cache-Control', 'no-store');
});

const GENERIC = 'If that account exists and has a recovery e-mail on file, a code has been sent.';

app.get('/api/health', async () => {
  const [ad, smtp] = await Promise.all([adHealth(), smtpHealth()]);
  return { ok: ad.ok && smtp.ok, ad, smtp, dry_run: cfg.dryRun, org: cfg.orgName };
});

app.get('/api/config', async () => ({
  org: cfg.orgName, it_contact: cfg.itContact, otp_ttl_min: cfg.otp.ttlMin, dry_run: cfg.dryRun,
}));

app.post('/api/challenge', async (req, reply) => {
  const username = String(req.body?.username || '').trim();
  const ip = req.ip;
  if (!username || username.length > 128) return reply.code(400).send({ error: 'bad_username', message: 'Enter your Windows username.' });
  if (!ipAllowed(ip)) {
    audit('challenge_ip_limited', { ip, username });
    return reply.code(429).send({ error: 'rate_limited', message: 'Too many requests from your network. Try again in 15 minutes.' });
  }

  let found;
  try { found = await findUser(username); }
  catch (e) {
    req.log.error({ err: e.message }, 'AD lookup failed');
    audit('challenge_ad_error', { ip, username, error: e.message });
    return reply.code(503).send({ error: 'ad_unreachable', message: 'The directory is unreachable right now. Try again shortly.' });
  }

  if (found.status !== 'ok') {
    audit('challenge_refused', { ip, username, reason: found.status, why: found.why, sam: found.user?.sam });
    // Same answer as success: no existence oracle.
    return { ok: true, message: GENERIC, expires_in_min: cfg.otp.ttlMin };
  }
  const { user } = found;
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(user.recoveryMail)) {
    audit('challenge_refused', { ip, username, sam: user.sam, reason: 'no_recovery_mail', attr: cfg.ad.recoveryMailAttr });
    return { ok: true, message: GENERIC, expires_in_min: cfg.otp.ttlMin };
  }
  if (resetsLast24h(user.sam.toLowerCase()) >= cfg.otp.resetsPerDay) {
    audit('challenge_refused', { ip, username, sam: user.sam, reason: 'daily_reset_limit' });
    return { ok: true, message: GENERIC, expires_in_min: cfg.otp.ttlMin };
  }
  if (!sendAllowed(user.sam.toLowerCase())) {
    audit('challenge_refused', { ip, username, sam: user.sam, reason: 'send_rate_limit' });
    return { ok: true, message: GENERIC, expires_in_min: cfg.otp.ttlMin };
  }

  const { id, code } = mintChallenge({ sam: user.sam, dn: user.dn });
  if (cfg.otp.debugLog) req.log.warn({ sam: user.sam, code }, 'OTP_DEBUG_LOG is on: code printed');
  try {
    await sendCode({ to: user.recoveryMail, code, account: user.sam, minutes: cfg.otp.ttlMin });
  } catch (e) {
    req.log.error({ err: e.message }, 'SMTP send failed');
    audit('challenge_mail_error', { ip, sam: user.sam, error: e.message });
    return reply.code(503).send({ error: 'mail_failed', message: 'We could not send the code right now. Try again shortly.' });
  }
  audit('challenge_sent', { ip, sam: user.sam, to: maskEmail(user.recoveryMail), challenge: id });
  return { ok: true, message: GENERIC, challenge_id: id, email_hint: maskEmail(user.recoveryMail), expires_in_min: cfg.otp.ttlMin };
});

app.post('/api/reset', async (req, reply) => {
  const username = String(req.body?.username || '').trim();
  const ip = req.ip;
  // The challenge binds the code to the sAMAccountName it was minted for; the
  // username here is only used to find that binding, never to pick a target.
  let found;
  try { found = await findUser(username); }
  catch (e) {
    return reply.code(503).send({ error: 'ad_unreachable', message: 'The directory is unreachable right now. Try again shortly.' });
  }
  const sam = found.user?.sam || username;
  const v = verifyChallenge({ id: req.body?.challenge_id, code: req.body?.code, sam });
  if (v.status !== 'ok') {
    audit('reset_code_rejected', { ip, sam, reason: v.status });
    const messages = {
      wrong_code: `That code is not right. ${v.attemptsLeft ?? 0} attempts left.`,
      expired: 'That code has expired. Request a new one.',
      already_used: 'That code has already been used. Request a new one.',
      max_attempts: 'Too many wrong codes. Request a new one.',
      not_found: 'That code is not valid. Request a new one.',
    };
    return reply.code(400).send({ error: v.status, message: messages[v.status] });
  }

  // Re-read the account NOW: status may have changed since the code was sent.
  if (found.status !== 'ok') {
    audit('reset_refused', { ip, sam, reason: found.status });
    return reply.code(409).send({ error: found.status, message: `This account cannot be reset here. Contact ${cfg.itContact}.` });
  }
  if (found.user.dn !== v.dn) {
    audit('reset_refused', { ip, sam, reason: 'dn_changed' });
    return reply.code(409).send({ error: 'dn_changed', message: 'The account changed since the code was sent. Start again.' });
  }

  const password = generatePassword();
  try {
    const r = await resetPassword(found.user.dn, password);
    audit('reset_ok', { ip, sam: found.user.sam, dn: found.user.dn, unlocked: r.unlocked, dry_run: r.dryRun === true, ua: req.headers['user-agent'] });
    return {
      ok: true,
      account: found.user.sam,
      display_name: found.user.displayName,
      password,
      unlocked: r.unlocked,
      dry_run: r.dryRun === true,
      must_change: cfg.ad.mustChangeAtLogon,
    };
  } catch (e) {
    req.log.error({ err: e.message }, 'AD reset failed');
    audit('reset_failed', { ip, sam: found.user.sam, error: e.message });
    return reply.code(503).send({ error: 'reset_failed', message: `The reset did not go through. Try again, or contact ${cfg.itContact}.` });
  }
});

app.listen({ host: cfg.host, port: cfg.port }).then(() => {
  app.log.info({ dryRun: cfg.dryRun, ad: `${cfg.ad.host}:${cfg.ad.port}`, base: cfg.ad.baseDN }, 'self-service reset up');
  if (cfg.dryRun) app.log.warn('RESET_DRY_RUN=true: passwords are NOT being written to AD');
});
