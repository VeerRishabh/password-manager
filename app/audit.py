"""Append-only audit log. Each row's hash covers the previous row's hash, so editing/deleting a row breaks the chain
(tamper-EVIDENT, not tamper-proof: someone with DB write access can rebuild the chain)."""
import hashlib, threading
from datetime import datetime, timezone
from .db import q
_lock = threading.Lock()

def _h(prev, user_id, ts, action, detail): return hashlib.sha256(f"{prev}|{user_id}|{ts}|{action}|{detail}".encode()).hexdigest()

def log(user_id, action, detail=""):
    with _lock:
        last = q("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", one=True)
        prev = last["hash"] if last else "0" * 64
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        q("INSERT INTO audit(user_id,ts,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
          (user_id, ts, action, detail, prev, _h(prev, user_id, ts, action, detail)))

def verify_chain() -> dict:
    prev = "0" * 64
    for r in q("SELECT * FROM audit ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _h(prev, r["user_id"], r["ts"], r["action"], r["detail"]):
            return {"ok": False, "broken_at_id": r["id"]}
        prev = r["hash"]
    return {"ok": True}

def for_user(user_id, limit=100):
    return [dict(id=r["id"], ts=r["ts"], action=r["action"], detail=r["detail"])
            for r in q("SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit))]
