# 🔐 Secure Password Manager

A web-based password vault (FastAPI + SQLite + AES-256-GCM). Runs locally; your data never leaves your machine.

## Features (all implemented)
User authentication (scrypt) · encrypted storage (everything, including site names, is inside one AES-GCM blob) · password generator (CSPRNG) · password-strength checker · search/filter by text and tag · **auto-lock** after inactivity (key destroyed server-side) · **audit log** with hash chain · **optional TOTP 2FA** (RFC 6238, implemented with the stdlib, works with Google Authenticator/Authy/1Password) · brute-force lockout · change master password (re-encrypts the vault atomically) · security headers · 12 tests.

## Run it
```bash
cd password-manager
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload                            # http://localhost:8000
pytest -q                                                # tests use a temp DB
```
Open http://localhost:8000, create a vault (the master password must score ≥ 3/4 on the strength meter), add entries, and try **Lock now**. API docs: `/docs`.

| Env var | Default | Meaning |
|---|---|---|
| `PM_DB` | `vault.db` | SQLite file path |
| `AUTOLOCK_SECONDS` | `300` | Idle time before the session key is destroyed (try `20` to see it) |
| `PM_SCRYPT_N` | `32768` | scrypt cost for NEW accounts (existing accounts store their own value). Raise for more security; don't lower it in real use |

**Enable 2FA:** `POST /2fa/setup` (via `/docs`) → add the returned `secret` to your authenticator app → `POST /2fa/enable` with the current code. From then on, login needs the code. It is not in the web UI, so use `/docs` or curl.

**PostgreSQL:** all SQL is in `app/db.py` (`q()` helper). To switch, replace it with psycopg/SQLAlchemy and change `?` placeholders to `%s`. Not included, to keep the project zero-setup.

## Design
```
Master password ──scrypt(salt, N=32768, r=8, p=1)──► 64 bytes
                                   ├─ first 32 → AES-256 key   (never stored; lives in RAM while unlocked)
                                   └─ last 32  → verifier      (stored; used to check the password)
Entry  = AES-256-GCM(key, JSON{site,user,password,url,notes,tags}, nonce=random 12B, AAD="entry:<user_id>")
Audit  = rows chained by SHA-256(prev_hash | user | time | action | detail)
```
Modules: `crypto.py` (the only place with crypto) · `passwords.py` · `sessions.py` (in-memory keys + auto-lock) · `audit.py` · `db.py` · `main.py` (API).

## API summary
`POST /register /login /lock /change-master` · `GET /session` · `POST /2fa/setup /2fa/enable /2fa/disable` · `POST|GET /entries`, `GET|PUT|DELETE /entries/{id}` · `POST /generate /strength` · `GET /audit /audit/verify`.
The entry **list never returns passwords**; revealing one (`GET /entries/{id}`) is written to the audit log.

## Security report
See [SECURITY_REPORT.md](SECURITY_REPORT.md): what this design defends against and, just as important, what it doesn't.

## Troubleshooting: errors you are likely to hit
| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: cryptography` | Dependencies not installed in the active venv | `pip install -r requirements.txt` (check the venv is activated) |
| `ValueError: Invalid parameter combination for scrypt` / memory limit exceeded | Very low-memory system or a bad `PM_SCRYPT_N` (must be a power of 2) | Use a power of two ≥ 1024; the default needs ~32 MB |
| `ModuleNotFoundError: No module named 'app'` | Wrong directory | `cd password-manager`, run `uvicorn app.main:app` |
| `422 Master password too weak` (score < 3) | Rejected on purpose | Use 4+ random words or 14+ mixed characters; see the returned `feedback` |
| `401 Invalid credentials` | Wrong username/password/2FA code. The message is deliberately identical for all causes | Check each; for 2FA, make sure your phone's clock is synced |
| `401 {"totp_required": true}` | 2FA is on and no code was sent | Add the 6-digit `totp` field |
| `429 Too many failed attempts` | 5 failures in 15 minutes | Wait 15 min (developer-only: `DELETE FROM attempts;`) |
| `401 Locked or not signed in` after a few minutes | Auto-lock did its job | Log in again; raise `AUTOLOCK_SECONDS` if needed |
| Everything locked after a server restart (`--reload` restarts on every code change) | Sessions live in memory by design | Log in again |
| `409 Username taken` | Username exists | Pick another or log in |
| `sqlite3.OperationalError: database is locked` | Another process has the DB open | Close DB viewers / the second server |
| `sqlite3.OperationalError: unable to open database file` | `PM_DB` directory missing or unwritable | Create the folder or unset the variable |
| **Forgot master password** | By design there is no recovery (the key is derived from it) | Restore a backup you can unlock; otherwise the data is gone |
| **Lost authenticator device** | The TOTP secret only exists in your app | You can't log in; save the setup secret somewhere safe when enabling 2FA |
| `500 ciphertext failed authentication` / `corrupted entry` | A DB row was modified or corrupted (tamper detection working) | Restore from backup |
| `/audit/verify` returns `ok:false` | A row was edited/deleted | `broken_at_id` tells you where to look |
| "Copy pw" does nothing | The clipboard API needs `localhost` or HTTPS | Use `http://localhost:8000` (not a LAN IP) or add TLS |
| Changed master password, then login fails | Old sessions are locked on purpose | Log in with the **new** password |
| Insecure over a network | Plain HTTP | Never expose it without TLS (Caddy/nginx reverse proxy) |
| `test_autolock` fails after editing it | The clock must be patched **before** registering | Patch `sessions.now` first, then create the session |
