import json, os, time
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from . import audit, crypto, db, passwords, sessions

db.init()
app = FastAPI(title="Secure Password Manager", docs_url="/docs")
STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60

@app.middleware("http")
async def headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                      "Referrer-Policy": "no-referrer",
                      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})
    return r

def ip(r: Request): return r.client.host if r.client else "?"

class Creds(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = None

class EntryIn(BaseModel):
    site: str = Field(min_length=1, max_length=200)
    username: str = Field("", max_length=200)
    password: str = Field(min_length=1, max_length=1000)
    url: str = Field("", max_length=500)
    notes: str = Field("", max_length=5000)
    tags: list[str] = []

def auth(authorization: str = Header(default="")):
    s = sessions.get(authorization[7:]) if authorization.startswith("Bearer ") else None
    if not s: raise HTTPException(401, "Locked or not signed in (auto-lock after inactivity). Please log in again.")
    s["token"] = authorization[7:]
    return s

def _aad(user_id): return f"entry:{user_id}".encode()
def _seal(s, data: dict): return crypto.encrypt(bytes(s["key"]), json.dumps(data).encode(), _aad(s["user_id"]))
def _open(s, blob): return json.loads(crypto.decrypt(bytes(s["key"]), blob, _aad(s["user_id"])))
def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ---------------- account ----------------
@app.post("/register")
def register(c: Creds, r: Request):
    st = passwords.strength(c.password)
    if st["score"] < 3: raise HTTPException(422, {"error": "Master password too weak", **st})
    if db.q("SELECT 1 FROM users WHERE username=?", (c.username,), one=True): raise HTTPException(409, "Username taken")
    salt, n = os.urandom(16), crypto.scrypt_n()
    key, av = crypto.derive(c.password, salt, n)
    uid = db.q("INSERT INTO users(username,salt,scrypt_n,auth_hash,created) VALUES(?,?,?,?,?)", (c.username, salt, n, av, _now()))
    audit.log(uid, "register", ip(r))
    return {"token": sessions.create(uid, c.username, key), "timeout": sessions.timeout()}

@app.post("/login")
def login(c: Creds, r: Request):
    cutoff = time.time() - FAIL_WINDOW
    fails = db.q("SELECT COUNT(*) n FROM attempts WHERE username=? AND ts>?", (c.username, cutoff), one=True)["n"]
    u = db.q("SELECT * FROM users WHERE username=?", (c.username,), one=True)
    if fails >= MAX_FAILS:
        audit.log(u["id"] if u else None, "login_blocked", f"{c.username} from {ip(r)}")
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    # Always run scrypt, even for unknown users, so response time doesn't reveal which usernames exist.
    key, av = crypto.derive(c.password, u["salt"] if u else b"\0" * 16, u["scrypt_n"] if u else crypto.scrypt_n())
    ok = bool(u) and crypto.verify(av, u["auth_hash"])
    if ok and u["totp_enabled"]:
        secret = crypto.decrypt(key, u["totp_enc"], b"totp").decode()
        if not c.totp or not crypto.totp_ok(secret, c.totp):
            ok = False
            if not c.totp: raise HTTPException(401, {"error": "2FA code required", "totp_required": True})
    if not ok:
        db.q("INSERT INTO attempts(username,ts) VALUES(?,?)", (c.username, time.time()))
        audit.log(u["id"] if u else None, "login_failed", f"{c.username} from {ip(r)}")
        raise HTTPException(401, "Invalid credentials")          # same message for every failure cause
    db.q("DELETE FROM attempts WHERE username=?", (c.username,))
    audit.log(u["id"], "login", ip(r))
    return {"token": sessions.create(u["id"], u["username"], key), "timeout": sessions.timeout()}

@app.post("/lock")
def lock(s=Depends(auth)):
    audit.log(s["user_id"], "lock", "manual"); sessions.destroy(s["token"]); return {"locked": True}

@app.get("/session")
def session(s=Depends(auth)): return {"username": s["username"], "seconds_left": sessions.seconds_left(s["token"])}

class ChangeMaster(BaseModel):
    old_password: str
    new_password: str

@app.post("/change-master")
def change_master(b: ChangeMaster, s=Depends(auth)):
    u = db.q("SELECT * FROM users WHERE id=?", (s["user_id"],), one=True)
    okey, oav = crypto.derive(b.old_password, u["salt"], u["scrypt_n"])
    if not crypto.verify(oav, u["auth_hash"]): raise HTTPException(401, "Old password incorrect")
    st = passwords.strength(b.new_password)
    if st["score"] < 3: raise HTTPException(422, {"error": "New master password too weak", **st})
    salt, n = os.urandom(16), crypto.scrypt_n()
    nkey, nav = crypto.derive(b.new_password, salt, n)
    rows = [(r["id"], crypto.encrypt(nkey, crypto.decrypt(okey, r["blob"], _aad(u["id"])), _aad(u["id"]))) for r in db.q("SELECT * FROM entries WHERE user_id=?", (u["id"],))]
    totp = crypto.encrypt(nkey, crypto.decrypt(okey, u["totp_enc"], b"totp"), b"totp") if u["totp_enc"] else None
    import sqlite3; from contextlib import closing      # one transaction: all-or-nothing re-encryption
    with closing(sqlite3.connect(db.path())) as c:
        with c:
            for i, b2 in rows: c.execute("UPDATE entries SET blob=? WHERE id=?", (b2, i))
            c.execute("UPDATE users SET salt=?,scrypt_n=?,auth_hash=?,totp_enc=? WHERE id=?", (salt, n, nav, totp, u["id"]))
    sessions.destroy_user(u["id"]); audit.log(u["id"], "change_master", "all sessions locked")
    return {"ok": True, "message": "Master password changed; please log in again"}

# ---------------- 2FA ----------------
@app.post("/2fa/setup")
def tfa_setup(s=Depends(auth)):
    secret = crypto.new_totp_secret()
    db.q("UPDATE users SET totp_enc=?, totp_enabled=0 WHERE id=?", (crypto.encrypt(bytes(s["key"]), secret.encode(), b"totp"), s["user_id"]))
    return {"secret": secret, "otpauth_uri": f"otpauth://totp/PasswordManager:{s['username']}?secret={secret}&issuer=PasswordManager"}

class Code(BaseModel): code: str

@app.post("/2fa/enable")
def tfa_enable(b: Code, s=Depends(auth)):
    u = db.q("SELECT totp_enc FROM users WHERE id=?", (s["user_id"],), one=True)
    if not u["totp_enc"]: raise HTTPException(409, "Call /2fa/setup first")
    if not crypto.totp_ok(crypto.decrypt(bytes(s["key"]), u["totp_enc"], b"totp").decode(), b.code): raise HTTPException(422, "Wrong code (check your phone's clock)")
    db.q("UPDATE users SET totp_enabled=1 WHERE id=?", (s["user_id"],)); audit.log(s["user_id"], "2fa_enabled"); return {"enabled": True}

@app.post("/2fa/disable")
def tfa_disable(b: Code, s=Depends(auth)):
    u = db.q("SELECT totp_enc,totp_enabled FROM users WHERE id=?", (s["user_id"],), one=True)
    if not u["totp_enabled"]: return {"enabled": False}
    if not crypto.totp_ok(crypto.decrypt(bytes(s["key"]), u["totp_enc"], b"totp").decode(), b.code): raise HTTPException(422, "Wrong code")
    db.q("UPDATE users SET totp_enabled=0, totp_enc=NULL WHERE id=?", (s["user_id"],)); audit.log(s["user_id"], "2fa_disabled"); return {"enabled": False}

# ---------------- vault ----------------
@app.post("/entries", status_code=201)
def add(e: EntryIn, s=Depends(auth)):
    eid = db.q("INSERT INTO entries(user_id,blob,updated) VALUES(?,?,?)", (s["user_id"], _seal(s, e.model_dump()), _now()))
    audit.log(s["user_id"], "entry_create", f"id={eid}"); return {"id": eid}

@app.get("/entries")
def list_entries(q: str = "", tag: str = "", s=Depends(auth)):
    """Everything (even site names) is encrypted, so search/filter decrypts in memory. Passwords are not returned here."""
    out = []
    for r in db.q("SELECT * FROM entries WHERE user_id=? ORDER BY id", (s["user_id"],)):
        try: d = _open(s, r["blob"])
        except crypto.DecryptError:
            out.append({"id": r["id"], "error": "corrupted entry"}); continue
        hay = " ".join([d["site"], d["username"], d["url"], *d["tags"]]).lower()
        if q.lower() in hay and (not tag or tag in d["tags"]):
            out.append({"id": r["id"], "site": d["site"], "username": d["username"], "url": d["url"], "tags": d["tags"],
                        "strength": passwords.strength(d["password"])["label"], "updated": r["updated"]})
    audit.log(s["user_id"], "entry_search", f"q={q!r} tag={tag!r} results={len(out)}")
    return out

def _row(eid, s):
    r = db.q("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, s["user_id"]), one=True)
    if not r: raise HTTPException(404, "Entry not found")      # 404 (not 403) so IDs of other users' entries aren't revealed
    return r

@app.get("/entries/{eid}")
def reveal(eid: int, s=Depends(auth)):
    r = _row(eid, s)
    try: d = _open(s, r["blob"])
    except crypto.DecryptError as e: raise HTTPException(500, str(e))
    audit.log(s["user_id"], "entry_reveal", f"id={eid} site={d['site']}"); return {"id": eid, **d}

@app.put("/entries/{eid}")
def update(eid: int, e: EntryIn, s=Depends(auth)):
    _row(eid, s); db.q("UPDATE entries SET blob=?, updated=? WHERE id=?", (_seal(s, e.model_dump()), _now(), eid))
    audit.log(s["user_id"], "entry_update", f"id={eid}"); return {"id": eid}

@app.delete("/entries/{eid}")
def delete(eid: int, s=Depends(auth)):
    _row(eid, s); db.q("DELETE FROM entries WHERE id=?", (eid,)); audit.log(s["user_id"], "entry_delete", f"id={eid}"); return {"deleted": eid}

# ---------------- tools / audit ----------------
class GenReq(BaseModel):
    length: int = 20; lower: bool = True; upper: bool = True; digits: bool = True; symbols: bool = True; avoid_ambiguous: bool = False

@app.post("/generate")
def generate(g: GenReq):
    try: pw = passwords.generate(**g.model_dump())
    except ValueError as e: raise HTTPException(422, str(e))
    return {"password": pw, **passwords.strength(pw)}

class PW(BaseModel): password: str

@app.post("/strength")
def strength(b: PW): return passwords.strength(b.password)

@app.get("/audit")
def get_audit(s=Depends(auth)): return audit.for_user(s["user_id"])

@app.get("/audit/verify")
def verify_audit(s=Depends(auth)): return audit.verify_chain()

@app.get("/")
def index(): return FileResponse(os.path.join(STATIC, "index.html"))
