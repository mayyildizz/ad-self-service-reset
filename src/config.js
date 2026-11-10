// All configuration comes from .env (or the process environment). Nothing
// site-specific lives in code: hostnames, DNs, group names and policies are
// all here so the same tree runs unchanged on any domain.
import 'dotenv/config';
import { readFileSync } from 'node:fs';

const bool = (v, d) => (v == null || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));
const num = (v, d) => (v == null || v === '' ? d : Number(v));
const list = (v) => String(v || '').split(',').map((s) => s.trim()).filter(Boolean);

const env = process.env;

const cfg = {
  env: env.NODE_ENV || 'development',
  host: env.HOST || '127.0.0.1',
  port: num(env.PORT, 3800),
  publicUrl: (env.PUBLIC_URL || 'http://localhost:3800').replace(/\/+$/, ''),
  // Only the proxy on this host is believed (deploy/nginx.conf.example): with a plain `true` the
  // FIRST X-Forwarded-For entry is the client, and that one is the caller's to invent. Not a hop
  // count: this Fastify answers a number by trusting nobody, so everyone would share one IP limit.
  // shortcut: a proxy on another machine is not believed, put its address here if that ever happens.
  trustProxy: bool(env.TRUST_PROXY, false) ? 'loopback' : false,
  orgName: env.ORG_NAME || 'Your organisation',
  itContact: env.IT_CONTACT || 'your IT helpdesk',

  ad: {
    host: env.AD_HOST || '',
    port: num(env.AD_PORT, 636),
    bindDN: env.AD_BIND_DN || '',
    bindPassword: env.AD_BIND_PASSWORD || '',
    baseDN: env.AD_BASE_DN || '',
    recoveryMailAttr: env.AD_RECOVERY_MAIL_ATTR || 'mail',
    protectedDnRegex: env.AD_PROTECTED_DN_REGEX ? new RegExp(env.AD_PROTECTED_DN_REGEX, 'i') : null,
    protectedGroups: list(env.AD_PROTECTED_GROUPS ?? 'Domain Admins,Enterprise Admins,Administrators,Schema Admins,Account Operators')
      .map((g) => g.toLowerCase()),
    mustChangeAtLogon: bool(env.AD_MUST_CHANGE_AT_LOGON, false),
    rejectUnauthorized: bool(env.AD_TLS_REJECT_UNAUTHORIZED, true),
    caCert: env.AD_CA_CERT ? readFileSync(env.AD_CA_CERT) : null,
    timeoutMs: num(env.AD_TIMEOUT_MS, 10000),
  },

  smtp: {
    host: env.SMTP_HOST || '',
    port: num(env.SMTP_PORT, 587),
    secure: bool(env.SMTP_SECURE, false),
    user: env.SMTP_USER || '',
    password: env.SMTP_PASSWORD || '',
    from: env.SMTP_FROM || env.SMTP_USER || '',
  },

  otp: {
    ttlMin: num(env.OTP_TTL_MIN, 10),
    maxAttempts: num(env.OTP_MAX_ATTEMPTS, 5),
    sendsPer15Min: num(env.OTP_SENDS_PER_15MIN, 3),
    challengesPerIp15Min: num(env.CHALLENGES_PER_IP_15MIN, 10),
    resetsPerDay: num(env.RESETS_PER_DAY, 3),
    debugLog: bool(env.OTP_DEBUG_LOG, false),
  },

  passwordLength: num(env.PASSWORD_LENGTH, 14),
  dryRun: bool(env.RESET_DRY_RUN, true),
  auditLog: env.AUDIT_LOG || './data/audit.jsonl',
};

/** Returns a list of human-readable problems; empty when the config is usable. */
export function validateConfig(c = cfg) {
  const problems = [];
  if (!c.ad.host) problems.push('AD_HOST is empty');
  if (!c.ad.bindDN) problems.push('AD_BIND_DN is empty');
  if (!c.ad.bindPassword) problems.push('AD_BIND_PASSWORD is empty');
  if (!c.ad.baseDN) problems.push('AD_BASE_DN is empty');
  if (!c.smtp.host) problems.push('SMTP_HOST is empty');
  if (!c.smtp.from) problems.push('SMTP_FROM is empty');
  if (c.env === 'production' && c.otp.debugLog) problems.push('OTP_DEBUG_LOG must be false when NODE_ENV=production');
  if (c.env === 'production' && !c.ad.rejectUnauthorized) problems.push('AD_TLS_REJECT_UNAUTHORIZED=false is not allowed in production; set AD_CA_CERT instead');
  if (c.passwordLength < 12) problems.push('PASSWORD_LENGTH must be at least 12');
  return problems;
}

export default cfg;
