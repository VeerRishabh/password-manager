"""In-memory unlocked sessions. The vault key exists ONLY here, and only while the session is active.
Auto-lock: any request after AUTOLOCK_SECONDS of inactivity destroys the key and requires a fresh login."""
import os, secrets, threading, time
now = time.monotonic                      # replaceable in tests
_lock = threading.Lock()
_s: dict[str, dict] = {}

def timeout() -> int: return int(os.getenv("AUTOLOCK_SECONDS", "300"))

def create(user_id: int, username: str, key: bytes) -> str:
    tok = secrets.token_urlsafe(32)
    with _lock: _s[tok] = {"user_id": user_id, "username": username, "key": bytearray(key), "last": now()}
    return tok

def get(tok: str):
    with _lock:
        for t in [t for t, s in _s.items() if now() - s["last"] > timeout()]: destroy_locked(t)   # sweep everyone
        s = _s.get(tok)
        if s: s["last"] = now()
        return s

def destroy_locked(tok):
    s = _s.pop(tok, None)
    if s:
        for i in range(len(s["key"])): s["key"][i] = 0          # best-effort zeroisation (Python may hold copies)

def destroy(tok):
    with _lock: destroy_locked(tok)

def destroy_user(user_id):
    with _lock:
        for t in [t for t, s in _s.items() if s["user_id"] == user_id]: destroy_locked(t)

def seconds_left(tok) -> int:
    s = _s.get(tok); return max(0, int(timeout() - (now() - s["last"]))) if s else 0
