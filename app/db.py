import os, sqlite3
from contextlib import closing

def path(): return os.getenv("PM_DB", "vault.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, scrypt_n INTEGER NOT NULL,
  auth_hash BLOB NOT NULL, totp_enc BLOB, totp_enabled INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blob BLOB NOT NULL, updated TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_entries_user ON entries(user_id);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, username TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, ts TEXT NOT NULL, action TEXT NOT NULL,
  detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""

def q(sql, args=(), one=False):
    """Run one statement, commit, return rows (list of sqlite3.Row) or a single row."""
    with closing(sqlite3.connect(path(), timeout=10)) as c:
        c.row_factory = sqlite3.Row; c.execute("PRAGMA foreign_keys=ON")
        cur = c.execute(sql, args); c.commit()
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else (rows if cur.description else cur.lastrowid)

def init():
    with closing(sqlite3.connect(path())) as c: c.executescript(SCHEMA); c.commit()
