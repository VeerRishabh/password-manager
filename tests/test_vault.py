import os, sqlite3, tempfile
os.environ["PM_DB"] = os.path.join(tempfile.mkdtemp(), "t.db"); os.environ["PM_SCRYPT_N"] = "1024"
import pytest
from fastapi.testclient import TestClient
from app import audit, crypto, passwords, sessions
from app.main import app

c = TestClient(app); PW = "Corr3ct-Horse-Battery-Staple!"
def reg(name, pw=PW):
    r = c.post("/register", json={"username": name, "password": pw}); assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}

# ---- crypto ----
def test_roundtrip_and_tamper_detection():
    k = os.urandom(32); blob = crypto.encrypt(k, b"secret", b"ctx")
    assert crypto.decrypt(k, blob, b"ctx") == b"secret"
    with pytest.raises(crypto.DecryptError): crypto.decrypt(k, blob[:-1] + bytes([blob[-1] ^ 1]), b"ctx")   # bit-flip
    with pytest.raises(crypto.DecryptError): crypto.decrypt(k, blob, b"other-ctx")                          # wrong context
    with pytest.raises(crypto.DecryptError): crypto.decrypt(os.urandom(32), blob, b"ctx")                   # wrong key
    assert crypto.encrypt(k, b"x", b"") != crypto.encrypt(k, b"x", b"")                                     # random nonces

def test_totp_rfc6238_vector():
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert crypto.totp(secret, at=59, digits=8) == "94287082"          # official RFC 6238 test vector

# ---- passwords ----
def test_generator_and_strength():
    pw = passwords.generate(24); assert len(pw) == 24 and any(ch.isdigit() for ch in pw) and any(ch.isupper() for ch in pw)
    assert passwords.strength("password")["score"] == 0 and passwords.strength("Password123")["score"] <= 2
    assert passwords.strength(pw)["score"] >= 3 and passwords.strength("abcabc123123")["score"] < 3

# ---- app ----
def test_weak_master_rejected():
    assert c.post("/register", json={"username": "weak", "password": "hunter2"}).status_code == 422

def test_nothing_plaintext_in_db():
    h = reg("eve"); c.post("/entries", json={"site": "MySecretSite", "username": "bob@x.com", "password": "Sup3rS3cret!"}, headers=h)
    raw = open(os.environ["PM_DB"], "rb").read()
    for needle in (b"MySecretSite", b"bob@x.com", b"Sup3rS3cret!"): assert needle not in raw

def test_crud_search_and_isolation():
    a, b = reg("alice"), reg("bob")
    eid = c.post("/entries", json={"site": "GitHub", "username": "al", "password": "pw-1-very-long", "tags": ["dev"]}, headers=a).json()["id"]
    assert c.get("/entries", params={"q": "git"}, headers=a).json()[0]["site"] == "GitHub"
    assert "password" not in c.get("/entries", headers=a).json()[0]                   # list never leaks passwords
    assert c.get("/entries", params={"tag": "nope"}, headers=a).json() == []
    assert c.get(f"/entries/{eid}", headers=a).json()["password"] == "pw-1-very-long"
    assert c.get(f"/entries/{eid}", headers=b).status_code == 404                     # other user can't read
    assert c.delete(f"/entries/{eid}", headers=b).status_code == 404
    c.put(f"/entries/{eid}", json={"site": "GitHub", "username": "al", "password": "changed-pw-123"}, headers=a)
    assert c.get(f"/entries/{eid}", headers=a).json()["password"] == "changed-pw-123"

def test_ciphertext_tampering_is_detected():
    h = reg("mallory"); eid = c.post("/entries", json={"site": "s", "password": "p"}, headers=h).json()["id"]
    con = sqlite3.connect(os.environ["PM_DB"]); blob = bytearray(con.execute("SELECT blob FROM entries WHERE id=?", (eid,)).fetchone()[0])
    blob[20] ^= 1; con.execute("UPDATE entries SET blob=? WHERE id=?", (bytes(blob), eid)); con.commit(); con.close()
    assert c.get(f"/entries/{eid}", headers=h).status_code == 500
    assert c.get("/entries", headers=h).json()[0]["error"] == "corrupted entry"

def test_autolock(monkeypatch):
    t = [1000.0]; monkeypatch.setattr(sessions, "now", lambda: t[0]); monkeypatch.setenv("AUTOLOCK_SECONDS", "60")
    h = reg("lockme")                                                                  # session created at fake t=1000
    t[0] += 30; assert c.get("/entries", headers=h).status_code == 200
    t[0] += 61; assert c.get("/entries", headers=h).status_code == 401                 # idle > 60s -> locked
    assert c.get("/entries", headers=h).status_code == 401                             # stays locked

def test_bruteforce_lockout_and_no_user_enumeration():
    reg("victim")
    msgs = {c.post("/login", json={"username": u, "password": "wrong"}).json()["detail"] for u in ["victim", "ghost"]}
    assert len(msgs) == 1                                                              # same error for known/unknown users
    for _ in range(5): c.post("/login", json={"username": "victim", "password": "wrong"})
    assert c.post("/login", json={"username": "victim", "password": PW}).status_code == 429   # even the right password is blocked

def test_2fa_flow():
    h = reg("twofa"); s = c.post("/2fa/setup", headers=h).json()["secret"]
    assert c.post("/2fa/enable", json={"code": "000000"}, headers=h).status_code == 422
    assert c.post("/2fa/enable", json={"code": crypto.totp(s)}, headers=h).status_code == 200
    r = c.post("/login", json={"username": "twofa", "password": PW}); assert r.status_code == 401 and r.json()["detail"]["totp_required"]
    assert c.post("/login", json={"username": "twofa", "password": PW, "totp": "123456"}).status_code == 401
    assert c.post("/login", json={"username": "twofa", "password": PW, "totp": crypto.totp(s)}).status_code == 200

def test_change_master_password():
    h = reg("rot"); eid = c.post("/entries", json={"site": "s", "password": "keepme-123"}, headers=h).json()["id"]
    NEW = "An0ther-Str0ng-Passphrase!!"
    assert c.post("/change-master", json={"old_password": PW, "new_password": NEW}, headers=h).status_code == 200
    assert c.get("/entries", headers=h).status_code == 401                             # old sessions killed
    t = c.post("/login", json={"username": "rot", "password": NEW}).json()["token"]
    assert c.get(f"/entries/{eid}", headers={"Authorization": "Bearer " + t}).json()["password"] == "keepme-123"
    assert c.post("/login", json={"username": "rot", "password": PW}).status_code == 401

def test_audit_log_and_tamper_evidence():
    h = reg("audited"); c.post("/entries", json={"site": "s", "password": "p"}, headers=h)
    actions = [a["action"] for a in c.get("/audit", headers=h).json()]; assert "entry_create" in actions and "register" in actions
    assert c.get("/audit/verify", headers=h).json()["ok"]
    con = sqlite3.connect(os.environ["PM_DB"]); con.execute("UPDATE audit SET detail='forged' WHERE id=(SELECT MIN(id) FROM audit)"); con.commit(); con.close()
    assert not c.get("/audit/verify", headers=h).json()["ok"]
