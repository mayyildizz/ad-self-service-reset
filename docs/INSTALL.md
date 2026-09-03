# Installation guide (end to end)

Time: about 45 minutes. You need a Domain Admin login for the Windows part and sudo on the Linux host.

Tested with Windows Server 2016–2022 domain controllers, Ubuntu 22.04/24.04 and Node.js 20/22.

---

## 1. Decide three things first

| Decision | Notes |
|---|---|
| **Which OU** holds the users allowed to self-reset | e.g. `OU=Staff,DC=corp,DC=example,DC=com`. Admin/service accounts must live *outside* it or in an OU matched by `AD_PROTECTED_DN_REGEX`. |
| **Which AD attribute** holds the recovery e-mail | Default `mail`. **If your mailbox password *is* the AD password (Exchange / M365 synced), a locked-out user cannot read that mailbox.** Put a personal address in `extensionAttribute1` (or `otherMailbox`) and set `AD_RECOVERY_MAIL_ATTR=extensionAttribute1`. |
| **Which SMTP account** sends the codes | Any relay. For Microsoft 365: a licensed mailbox with *Authenticated SMTP* enabled, `smtp.office365.com:587`. |

---

## 2. Windows: create the service account and delegate (5 min)

On a DC, elevated PowerShell:

```powershell
# from the repo's deploy/ folder (copy the file over, or paste it)
.\delegate-permissions.ps1 -TargetOU "OU=Staff,DC=corp,DC=example,DC=com" -ServiceAccount svc-pwreset
```

It creates `svc-pwreset` (password never expires, cannot change password) and grants it, on that OU only:

- *Reset Password* extended right on user objects
- write `lockoutTime` and `pwdLastSet` on user objects

Nothing else. Do **not** put this account in any admin group.

Manual alternative: ADUC → right-click the OU → *Delegate Control* → add the account → *Reset user passwords and force password change at next logon*. Then in *Advanced Security* add *Write lockoutTime* for descendant user objects.

---

## 3. Windows: enable LDAPS on the domain controller (10 min)

Password writes are only accepted over TLS. Check whether 636 already answers:

```powershell
Test-NetConnection dc1.corp.example.com -Port 636
```

If it is closed:

**Option A – you have an internal CA (AD CS):** issue a *Kerberos Authentication* or *Domain Controller* certificate to the DC (auto-enrolment usually does this). Restart the DC or wait a few minutes; 636 opens automatically.

**Option B – no CA:** create a self-signed certificate on the DC:

```powershell
$dc = "dc1.corp.example.com"
$cert = New-SelfSignedCertificate -DnsName $dc -CertStoreLocation cert:\LocalMachine\My `
  -KeyUsage DigitalSignature,KeyEncipherment -Provider "Microsoft RSA SChannel Cryptographic Provider" `
  -NotAfter (Get-Date).AddYears(5)
# Tell AD DS to use it (the NTDS store):
$cert | Export-Certificate -FilePath C:\dc-ldaps.cer
Import-Certificate -FilePath C:\dc-ldaps.cer -CertStoreLocation cert:\LocalMachine\Root   # trust it locally
Restart-Service NTDS -Force
```

Export the certificate (public part) you will trust from Linux:

```powershell
$cert | Export-Certificate -FilePath C:\dc-ldaps.cer     # DER
# or, with an internal CA, export the CA root instead:
# certutil -ca.cert C:\ca-root.cer
```

Open TCP 636 from the Linux host to the DC on any firewall in between.

---

## 4. Linux: install the app (10 min)

```bash
sudo apt-get update && sudo apt-get install -y git curl          # Debian/Ubuntu
git clone https://github.com/mayyildizz/ad-self-service-reset.git
cd ad-self-service-reset
```

Copy the certificate from step 3 and convert it to PEM:

```bash
# copy dc-ldaps.cer (or ca-root.cer) here, then:
openssl x509 -inform der -in dc-ldaps.cer -out dc-ldaps.pem   # skip if already PEM (starts with -----BEGIN)
sudo mkdir -p /etc/ad-self-service && sudo cp dc-ldaps.pem /etc/ad-self-service/ca.pem
```

Check the TLS handshake from Linux before going further:

```bash
openssl s_client -connect dc1.corp.example.com:636 -CAfile /etc/ad-self-service/ca.pem </dev/null 2>/dev/null | grep -E "Verify return|subject="
# want: Verify return code: 0 (ok)
```

> The hostname you use in `AD_HOST` must appear in the certificate's subject/SAN. Use the FQDN, not the IP.

Run the guided installer:

```bash
./scripts/setup.sh
```

It installs Node.js if needed, asks every setting (use the values from steps 1–3, and `/etc/ad-self-service/ca.pem` for the CA), writes `.env`, runs the verification, and installs a systemd service. Leave **dry run = true** for now.

---

## 5. Linux: verify (5 min)

```bash
npm run check -- --user jsmith --mail you@example.com
```

Expect every line to be ✔. Meaning of failures:

| Message | Fix |
|---|---|
| bind failed: self signed certificate / unable to verify | `AD_CA_CERT` wrong file, or `AD_HOST` not the name in the certificate |
| ECONNREFUSED / ETIMEDOUT on 636 | LDAPS not enabled (step 3) or firewall |
| invalidCredentials / data 52e | wrong `AD_BIND_DN` or password. Use `svc-pwreset@corp.example.com` |
| not found under AD_BASE_DN | the test user is not inside that OU |
| recovery e-mail EMPTY | fill the attribute on the user (step 1) |
| SMTP failed: 535 | wrong SMTP login; on M365 enable *Authenticated SMTP* for the mailbox |

---

## 6. Put it behind HTTPS (optional but recommended, 5 min)

Users will type a code and read a password on this page, so serve it over TLS.

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/reset && sudo ln -s /etc/nginx/sites-available/reset /etc/nginx/sites-enabled/
sudo sed -i 's/reset.example.com/reset.YOURDOMAIN/g' /etc/nginx/sites-available/reset
sudo certbot --nginx -d reset.YOURDOMAIN
```

In `.env` set `HOST=127.0.0.1`, `TRUST_PROXY=true`, `PUBLIC_URL=https://reset.YOURDOMAIN`, then `sudo systemctl restart ad-self-service`.

---

## 7. End-to-end test, then go live

1. Open the page, enter the **test user**, receive the code, enter it. You get a password and the banner *TEST MODE: the password was NOT actually changed*. Check `data/audit.jsonl` shows `challenge_sent` and `reset_ok` with `"dry_run":true`.
2. Try an admin username. You must get the generic message and **no** e-mail; the audit log shows `challenge_refused ... protected`.
3. Do one real reset from the command line:
   ```bash
   sed -i 's/^RESET_DRY_RUN=.*/RESET_DRY_RUN=false/' .env
   npm run check -- --user jsmith --reset        # answer y
   ```
   Log in to Windows (or `ldapwhoami -H ldaps://dc1... -D jsmith@corp.example.com -W`) with the printed password.
4. Restart the service to pick up the change: `sudo systemctl restart ad-self-service`.
5. Do one real reset through the web page with the test user.

You are live. Tell users the URL.

---

## 8. Operating it

| Task | Command |
|---|---|
| Logs | `journalctl -u ad-self-service -f` |
| Audit trail | `tail -f data/audit.jsonl` (one JSON per line; `event` = challenge_sent / challenge_refused / reset_ok / reset_failed ...) |
| Change settings | edit `.env`, `sudo systemctl restart ad-self-service` |
| Update | `git pull && npm install --omit=dev && sudo systemctl restart ad-self-service` |
| Health | `curl -s localhost:3800/api/health` |
| Rotate service account password | change in AD, update `AD_BIND_PASSWORD`, restart |

The app keeps no database. Stopping it voids any codes in flight, nothing else.
