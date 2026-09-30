# Security Report: Password Manager

**Scope:** a single-host web application for one or a few users, run locally. **Status:** portfolio project, not externally audited.

## Assets
Vault entries (passwords, usernames, notes, site names) · master password · TOTP secret · audit log integrity.

## What is protected, and how
| Threat | Defence | Evidence |
|---|---|---|
| **Stolen database file** (backup leak, disk theft) | All entry fields and the TOTP secret are AES-256-GCM encrypted under a key derived from the master password. The key is never written to disk. Site names are encrypted too | `test_nothing_plaintext_in_db` greps the raw DB file |
| **Offline password guessing** against a stolen DB | scrypt (memory-hard, N=2^15, per-user 16-byte random salt): each guess costs ~32 MB and ~0.1 s, which is hostile to GPUs/ASICs. Weak master passwords are refused at registration | `register` enforces score ≥ 3 |
| **Ciphertext tampering / swapping** | GCM authentication tag; AAD binds blobs to the owning user, so another user's blob can't be spliced in | `test_ciphertext_tampering_is_detected`, `test_roundtrip_and_tamper_detection` |
| **Nonce reuse** | Fresh random 96-bit nonce per encryption (negligible collision probability at this scale) | `test_roundtrip...` |
| **Online brute force** | 5 failures / 15 min per username, then 429, even for the correct password | `test_bruteforce_lockout...` |
| **Username enumeration** | Identical error for wrong user/password/2FA; scrypt runs even for unknown users to equalise timing | same test |
| **Cross-user access (IDOR)** | Every query is scoped by the session's `user_id`; foreign IDs return 404 | `test_crud_search_and_isolation` |
| **Unattended unlocked session** | Auto-lock: after the idle timeout the in-memory key is zeroed and the session deleted | `test_autolock` |
| **Guessed/phished master password** | Optional TOTP 2FA, checked with the password; secret stored encrypted | `test_2fa_flow`, RFC 6238 vector test |
| **Log tampering** | Audit rows are hash-chained; `/audit/verify` detects edits/deletions | `test_audit_log_and_tamper_evidence` |
| **Over-exposure via the API** | The list endpoint never returns passwords; each reveal is audit-logged | tests |
| **XSS / clickjacking / caching** | UI escapes output; CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store`; token kept in JS memory (not localStorage) | headers checked on the live server |
| **SQL injection** | Parameterised queries only | code review |
| **Weak generated passwords** | `secrets` (OS CSPRNG), one char per chosen class, CSPRNG shuffle | `test_generator_and_strength` |

## What it does NOT protect against
1. **A compromised host** (malware, keylogger, memory scraping). While unlocked, the key is in RAM, and Python can't guarantee zeroisation.
2. **A weak-but-passing master password.** The meter is a heuristic; dictionary attacks on a stolen DB are still feasible against guessable passphrases.
3. **Plain HTTP.** Over a network, tokens and master passwords can be sniffed. Use localhost or put TLS in front.
4. **A lost master password.** No recovery, no key escrow.
5. **The server operator.** The server sees the master password and plaintext entries during requests. A zero-knowledge, client-side-crypto design (like Bitwarden) would remove this; this project isn't one.
6. **Metadata leakage.** Entry count, blob sizes, timestamps and account usernames are visible to anyone with the DB.
7. **Audit log rebuild.** The chain detects edits, but someone with write access can recompute every hash. Anchoring the latest hash externally would fix that.
8. **Session token theft.** The bearer token grants access until auto-lock; there's no device binding. XSS or a malicious browser extension could steal it.
9. **Clipboard exposure.** Copied passwords sit in the OS clipboard (cleared after 20 s from the UI, best effort); clipboard managers may keep them.
10. **Targeted lockout.** Lockout is per username, so an attacker can lock a victim out. There's no global rate limiting.
11. **Breach checking.** It doesn't query breach corpora (e.g. Have I Been Pwned), and the common-password list is tiny.
12. **TOTP limits.** No recovery codes, and replay inside the 30 s window isn't blocked.
13. **No expert audit.** It uses vetted primitives (`cryptography`, stdlib scrypt/HMAC), but the composition is unreviewed.

## Possible hardening
Argon2id, client-side encryption, recovery codes, TOTP replay cache, persistent rate limiting, HIBP k-anonymity checks, OS keyring integration, external log anchoring, PostgreSQL.
