import nodemailer from 'nodemailer';
import cfg from './config.js';

let transport;
export function mailer() {
  if (!transport) {
    transport = nodemailer.createTransport({
      host: cfg.smtp.host,
      port: cfg.smtp.port,
      secure: cfg.smtp.secure,
      auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.password } : undefined,
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
      socketTimeout: 20_000,
    });
  }
  return transport;
}

export async function smtpHealth() {
  try { await mailer().verify(); return { ok: true }; }
  catch (e) { return { ok: false, error: e.message }; }
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export async function sendCode({ to, code, account, minutes }) {
  const subject = `Confirm your ${cfg.orgName} Windows password reset: ${code}`;
  const text = [
    `You asked to reset the Windows password for account "${account}".`,
    ``,
    `Your confirmation code is: ${code}`,
    ``,
    `It expires in ${minutes} minutes and works once.`,
    `If you did not request this, ignore this e-mail; nothing has changed. If these keep arriving, tell ${cfg.itContact}.`,
    ``,
    `${cfg.orgName} - IT Self Service`,
  ].join('\n');
  const html = `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;font-size:15px;line-height:1.6;color:#111">
<p>You asked to reset the Windows password for account <b>${esc(account)}</b>. Enter this code to confirm:</p>
<p style="font-size:30px;font-weight:800;letter-spacing:6px;margin:14px 0">${esc(code)}</p>
<p>This code expires in ${minutes} minutes and works once. If you did not request it, ignore this e-mail; nothing has changed. If these keep arriving, tell ${esc(cfg.itContact)}: somebody else may be trying to use your account.</p>
<p style="color:#666">${esc(cfg.orgName)} · IT Self Service</p>
</div>`;
  await mailer().sendMail({ from: cfg.smtp.from, to, subject, text, html });
}

export async function sendTest(to) {
  await mailer().sendMail({
    from: cfg.smtp.from, to,
    subject: `${cfg.orgName} self-service reset: SMTP test`,
    text: 'If you can read this, outgoing mail from the self-service reset server works.',
  });
}
