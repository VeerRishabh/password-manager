"""All cryptography lives here. Master password -> scrypt -> 64 bytes: first 32 = encryption key (never stored),
last 32 = authentication verifier (stored). Data is encrypted with AES-256-GCM (authenticated encryption)."""
import base64, hashlib, hmac, os, struct, time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_N = 2 ** 15                                   # ~32 MB, ~100ms. Tests lower it via PM_SCRYPT_N.
def scrypt_n() -> int: return int(os.getenv("PM_SCRYPT_N", DEFAULT_N))

def derive(password: str, salt: bytes, n: int) -> tuple[bytes, bytes]:
    k = hashlib.scrypt(password.encode(), salt=salt, n=n, r=8, p=1, dklen=64, maxmem=2 ** 28)
    return k[:32], k[32:]                              # (enc_key, auth_verifier)

def verify(a: bytes, b: bytes) -> bool: return hmac.compare_digest(a, b)

class DecryptError(Exception): pass

def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)                             # fresh random nonce per encryption
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try: return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag: raise DecryptError("ciphertext failed authentication (tampered, wrong key, or wrong context)")

# ---- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30s) implemented with the stdlib ----
def new_totp_secret() -> str: return base64.b32encode(os.urandom(20)).decode().rstrip("=")

def totp(secret_b32: str, at: float | None = None, digits=6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if at is None else at) // 30)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)

def totp_ok(secret_b32: str, code: str, at: float | None = None) -> bool:
    t = time.time() if at is None else at
    return any(hmac.compare_digest(totp(secret_b32, t + d * 30), code.strip()) for d in (-1, 0, 1))
