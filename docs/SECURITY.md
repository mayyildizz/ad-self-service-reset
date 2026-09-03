# Security model

**What proves identity:** possession of the recovery mailbox stored in AD (`AD_RECOVERY_MAIL_ATTR`).
That is the entire trust chain. If that attribute can be written by the user, or the mailbox is
protected by the very password being reset, the page is only as strong as that weakness. Choose
the attribute accordingly (see INSTALL.md §1).

## Controls

| Threat | Control |
|---|---|
| Enumerating usernames | `/api/challenge` returns the same body for unknown, refused and successful requests. Only the audit log knows. |
| Guessing the code | 6 digits, 5 attempts, 10-minute life, single use. Hash stored, never the code. |
| Reusing a code | Burned atomically before the reset runs; a second use returns `already_used`. |
| Code minted for user A used for user B | Challenge is bound to the sAMAccountName and DN it was minted for. |
| Account moved/disabled/promoted between challenge and reset | Account is re-read from AD at reset time and refused if its status or DN changed. |
| Resetting privileged accounts | Refused if `adminCount=1`, member of any `AD_PROTECTED_GROUPS`, or DN matches `AD_PROTECTED_DN_REGEX`. |
| Resetting outside scope | All searches are rooted at `AD_BASE_DN`; the service account is only delegated on that OU. |
| Mail bombing a user | 3 codes per account per 15 min, 10 challenges per IP per 15 min, 3 resets per account per day. |
| Password interception | LDAPS only (AD refuses cleartext writes anyway). Certificate validation is enforced in production; `AD_TLS_REJECT_UNAUTHORIZED=false` is rejected when `NODE_ENV=production`. Put nginx+TLS in front of the page. |
| Weak generated passwords | 14+ chars, CSPRNG, one of each class, unambiguous alphabet. |
| Leaking the service account | `.env` is mode 600 and git-ignored. The systemd unit runs unprivileged with `ProtectSystem=full`. |
| Debug leakage | `OTP_DEBUG_LOG` prints codes to the log for testing and is refused when `NODE_ENV=production`. |

## Things you still own

- Restrict who can reach the page (VPN, firewall) if you do not want it on the open internet.
- Rotate the service account password periodically.
- Review `data/audit.jsonl`; repeated `challenge_refused` with reason `protected` from one IP is someone probing.
- The audit log contains usernames and masked e-mails, no codes and no passwords. Protect it like any log.

## Reporting

Open a GitHub issue for anything that is not a live vulnerability. For a live vulnerability,
e-mail the repository owner instead.
