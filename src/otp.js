// In-memory one-time codes and rate limits. The process is the only writer,
// codes live minutes, and a restart voiding open challenges is acceptable, so
// no database is needed. Only SHA-256 hashes of codes are kept.
import { createHash, randomInt, randomBytes } from 'node:crypto';
import cfg from './config.js';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const challenges = new Map();       // challengeId -> {samKey, dn, sam, codeHash, attempts, expiresAt, consumed}
const sendLog = new Map();          // samKey -> [timestamps]
const ipLog = new Map();            // ip -> [timestamps]

const WINDOW = 15 * 60 * 1000;
function bump(map, key, limit) {
  const now = Date.now();
  const arr = (map.get(key) || []).filter((t) => now - t < WINDOW);
  if (arr.length >= limit) { map.set(key, arr); return false; }
  arr.push(now);
  map.set(key, arr);
  return true;
}

export const ipAllowed = (ip) => bump(ipLog, ip, cfg.otp.challengesPerIp15Min);
export const sendAllowed = (samKey) => bump(sendLog, samKey, cfg.otp.sendsPer15Min);

export function mintChallenge({ sam, dn }) {
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  const id = randomBytes(16).toString('hex');
  challenges.set(id, {
    samKey: sam.toLowerCase(), sam, dn, codeHash: sha(code), attempts: 0,
    expiresAt: Date.now() + cfg.otp.ttlMin * 60 * 1000, consumed: false,
  });
  return { id, code };
}

/**
 * Verify and BURN a code in one step. Burning happens before the reset runs,
 * so a code that authorised one attempt can never authorise a second.
 * → { status:'ok', sam, dn } | 'not_found' | 'expired' | 'already_used' | 'max_attempts' | { status:'wrong_code', attemptsLeft }
 */
export function verifyChallenge({ id, code, sam }) {
  const c = challenges.get(String(id || ''));
  if (!c) return { status: 'not_found' };
  if (c.samKey !== String(sam || '').toLowerCase()) return { status: 'not_found' };
  if (c.consumed) return { status: 'already_used' };
  if (Date.now() > c.expiresAt) { challenges.delete(id); return { status: 'expired' }; }
  if (c.attempts >= cfg.otp.maxAttempts) return { status: 'max_attempts' };
  if (sha(String(code || '').trim()) !== c.codeHash) {
    c.attempts++;
    return { status: 'wrong_code', attemptsLeft: Math.max(0, cfg.otp.maxAttempts - c.attempts) };
  }
  c.consumed = true;
  return { status: 'ok', sam: c.sam, dn: c.dn };
}

// Housekeeping: drop expired challenges so the map cannot grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) if (now > c.expiresAt + 60_000) challenges.delete(id);
}, 60_000).unref();

export function maskEmail(email) {
  const [user, domain] = String(email).split('@');
  const shown = user.length <= 2 ? user[0] + '*' : user.slice(0, 2) + '***';
  return `${shown}@${domain}`;
}
