// Append-only JSON-lines audit trail. One object per line, never rewritten.
import { appendFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import cfg from './config.js';

export function audit(event, fields = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...fields });
  try {
    mkdirSync(dirname(cfg.auditLog), { recursive: true });
    appendFileSync(cfg.auditLog, line + '\n');
  } catch (e) {
    console.error('audit write failed:', e.message, line);
  }
}

/** Successful resets for one account (lower-cased sAMAccountName) in the last 24h. */
export function resetsLast24h(sam) {
  if (!existsSync(cfg.auditLog)) return 0;
  const since = Date.now() - 24 * 3600 * 1000;
  let n = 0;
  for (const line of readFileSync(cfg.auditLog, 'utf8').split('\n')) {
    if (!line) continue;
    try {
      const o = JSON.parse(line);
      if (o.event === 'reset_ok' && o.sam === sam && Date.parse(o.ts) > since) n++;
    } catch { /* skip malformed */ }
  }
  return n;
}
