"""Password generator + strength checker."""
import math, re, secrets, string

COMMON = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "monkey", "iloveyou", "admin", "welcome",
          "password1", "passw0rd", "123456789", "111111", "dragon", "football", "baseball", "sunshine", "master", "login"}
SEQS = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]

def generate(length=20, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False) -> str:
    pools = [(lower, string.ascii_lowercase), (upper, string.ascii_uppercase), (digits, string.digits), (symbols, "!@#$%^&*()-_=+[]{};:,.?")]
    pools = [p.translate(str.maketrans("", "", "Il1O0o")) if avoid_ambiguous else p for on, p in pools if on]
    if not pools: raise ValueError("Select at least one character class")
    if not 8 <= length <= 128: raise ValueError("Length must be 8..128")
    if length < len(pools): raise ValueError("Length too short for selected classes")
    chars = [secrets.choice(p) for p in pools]                      # guarantee one from each class
    allc = "".join(pools)
    chars += [secrets.choice(allc) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)                           # CSPRNG shuffle
    return "".join(chars)

def strength(pw: str) -> dict:
    fb = []
    if not pw: return {"score": 0, "label": "empty", "entropy_bits": 0, "feedback": ["Enter a password"]}
    low = pw.lower()
    if low in COMMON or re.sub(r"[\d!@#$%^&*]+$", "", low) in COMMON:
        return {"score": 0, "label": "very weak", "entropy_bits": 0, "feedback": ["This is one of the most common passwords"]}
    pool = 26 * bool(re.search("[a-z]", pw)) + 26 * bool(re.search("[A-Z]", pw)) + 10 * bool(re.search(r"\d", pw)) + 32 * bool(re.search(r"[^A-Za-z0-9]", pw))
    eff = len(pw)
    eff -= sum(len(m.group(0)) - 1 for m in re.finditer(r"(.)\1+", pw))                 # repeated characters add little
    for s in SEQS:                                                                       # ascending/descending runs of 3+
        for rev in (s, s[::-1]):
            for i in range(len(rev) - 2):
                if rev[i:i + 3] in low: eff -= 2; fb.append("Avoid sequences like 'abc' or '123'"); break
    eff = max(eff, 1)
    bits = round(eff * math.log2(max(pool, 2)), 1)
    if len(pw) < 12: fb.append("Use at least 12 characters")
    if pool < 62: fb.append("Mix upper/lower case, digits and symbols")
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    return {"score": score, "label": ["very weak", "weak", "fair", "strong", "very strong"][score], "entropy_bits": bits, "feedback": sorted(set(fb))}
