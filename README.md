# AD Self-Service Password Reset

A small web app that lets your users reset their own Active Directory (Windows) password
without calling IT. It runs on a Linux server, talks **LDAPS** to your domain controller, and
proves identity with a **6-digit one-time code e-mailed to the recovery address stored in AD**.

```
user ──▶ https://reset.example.com ──▶ Node.js app (Linux) ──LDAPS 636──▶ Domain Controller
                                            │
                                            └──SMTP──▶ one-time code to the user's recovery e-mail
```

**Flow:** username → code e-mailed → code entered → new password shown (account is also unlocked).

## Features

- Least-privilege: the service account only needs *Reset Password* + write `lockoutTime`/`pwdLastSet`
  on one OU. A PowerShell script sets that delegation up for you.
- Refuses admin accounts (`adminCount=1`, Domain Admins etc., protected OUs) and disabled accounts.
- No account-existence oracle: unknown, refused and successful requests all get the same answer.
- One-time codes: hashed, 10-minute life, 5 attempts, single use, bound to one account.
- Rate limits per IP, per account, and a daily reset cap.
- Append-only JSON audit log of every request.
- **Dry-run mode** so you can test the whole flow before a single password is written.
- Zero native dependencies: `npm install` works on any Linux with Node.js 20+.

## Quick start

```bash
git clone https://github.com/mayyildizz/ad-self-service-reset.git
cd ad-self-service-reset
./scripts/setup.sh        # guided: installs Node, asks every setting, writes .env, verifies, installs systemd unit
```

Then follow **[docs/INSTALL.md](docs/INSTALL.md)** for the Windows side (LDAPS, service account
delegation, recovery e-mail attribute) and the end-to-end test.

## Requirements

| Where | What |
|---|---|
| Windows | Active Directory domain; LDAPS (TCP 636) enabled on at least one DC; a delegated service account |
| Linux host | Debian/Ubuntu or RHEL-family; Node.js 20+ (installer can add it); outbound TCP 636 to the DC and 587/465 to your SMTP server |
| Mail | Any SMTP server/relay (Microsoft 365, Google Workspace, Postfix, ...) |
| Optional | nginx + TLS certificate in front of the app |

## Files

```
src/server.js     HTTP API (+ static page)         scripts/setup.sh          guided installer
src/ad.js         LDAPS lookup / reset / unlock    scripts/check.js          verification tool
src/otp.js        one-time codes + rate limits     deploy/delegate-permissions.ps1   AD delegation (run on Windows)
src/mailer.js     SMTP                             deploy/ad-self-service.service    systemd unit
src/audit.js      JSON-lines audit log             deploy/nginx.conf.example         reverse proxy
public/index.html the user-facing page             docs/INSTALL.md, docs/SECURITY.md
```

## Configuration

Everything is in `.env` (copy `.env.example`, every key is documented there). The installer writes it
for you. Key settings:

| Key | Meaning |
|---|---|
| `AD_HOST`, `AD_BIND_DN`, `AD_BIND_PASSWORD` | DC hostname and the delegated service account |
| `AD_BASE_DN` | Only users under this OU can be reset |
| `AD_RECOVERY_MAIL_ATTR` | AD attribute holding the address the code goes to (`mail` by default) |
| `AD_PROTECTED_DN_REGEX`, `AD_PROTECTED_GROUPS` | Accounts the page must never touch |
| `AD_CA_CERT` | Your internal CA certificate (PEM) so the DC's LDAPS certificate is trusted |
| `SMTP_*` | Outgoing mail |
| `RESET_DRY_RUN` | `true` = full flow, no AD write. Start here. |

## Verify

```bash
npm run check                                  # config, LDAPS bind, SMTP auth
npm run check -- --user jsmith --mail me@x.com # + account lookup + test e-mail
npm run check -- --user jsmith --reset         # real reset of a test account (asks for confirmation)
curl -s localhost:3800/api/health
```

## License

MIT
