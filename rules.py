"""
Rule table for CryptoRot.
Base severities come straight from the Phase 1 scoring design. If these
numbers change, Phase 1 needs to change too, so I'm keeping them fixed
here instead of hardcoding them again inside scorer.py.
"""
# primitive_id -> (category, base_severity, human_name, remediation)
RULES = {
    "hardcoded_key": (
        "classical",
        95,
        "Hardcoded key / secret",
        "Move to environment variables or a secrets manager (e.g. AWS "
        "Secrets Manager, HashiCorp Vault). Rotate the exposed key.",
    ),
    "md5": (
        "classical",
        90,
        "MD5 hash",
        "Replace with SHA-256 or SHA-3 for integrity/checksum use, or a "
        "dedicated password hash (bcrypt/argon2) if used for passwords.",
    ),
    "ecb_mode": (
        "classical",
        85,
        "AES/DES in ECB mode",
        "Switch to an authenticated mode such as AES-GCM.",
    ),
    "sha1": (
        "classical",
        80,
        "SHA-1 hash",
        "Replace with SHA-256 or SHA-3.",
    ),
    "rsa": (
        "quantum",
        40,
        "RSA key generation",
        "Plan migration to ML-KEM (FIPS 203) for key exchange or ML-DSA "
        "(FIPS 204) for signatures.",
    ),
    "ecdsa": (
        "quantum",
        40,
        "ECDSA / EC key generation",
        "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
    ),
    "dh": (
        "quantum",
        40,
        "Diffie-Hellman key exchange",
        "Plan migration to ML-KEM (FIPS 203).",
    ),
}
# Dotted call-name patterns that map directly to a primitive.
# Matched against the fully-resolved call name, e.g. "hashlib.md5".
CALL_PATTERNS = {
    "hashlib.md5": "md5",
    "Crypto.Hash.MD5.new": "md5",
    "hashlib.sha1": "sha1",
    "Crypto.Hash.SHA1.new": "sha1",
    "rsa.generate_private_key": "rsa",
    "RSA.generate": "rsa",
    "rsa.newkeys": "rsa",
    "ec.generate_private_key": "ecdsa",
    "ECC.generate": "ecdsa",
    "SigningKey.generate": "ecdsa",
    "dh.generate_parameters": "dh",
    "DH.generate_parameters": "dh",
}
# covers hashlib.new("md5", ...) and hashlib.new("sha1", ...), where the
# algorithm name is the first argument instead of part of the call name
HASHLIB_NEW_ALGOS = {"md5": "md5", "sha1": "sha1"}
# Any attribute access ending in one of these names flags ECB mode,
# e.g. AES.MODE_ECB, DES3.MODE_ECB
ECB_ATTR_SUFFIXES = {"MODE_ECB"}
# Variable-name regex fragments that mark an assignment as a candidate
# hardcoded secret (case-insensitive substring match)
SECRET_NAME_HINTS = ("key", "secret", "password", "passwd", "token", "api_key")
# Path substrings, matched case-insensitively against the file's relative path
SECURITY_PATH_HINTS = ("auth", "login", "session", "token", "crypto", "secret")
TEST_PATH_HINTS = ("test", "spec", "mock")
# One-line, plain-language explanations, shown in the CLI's breakdown
# next to the fix.
PLAIN_EXPLANATIONS = {
    "hardcoded_key": "A real password or key sits directly in the source code, in plain text.",
    "md5": "MD5 was broken back in 2004. It doesn't take much to make two different files hash to the same value.",
    "ecb_mode": "ECB encrypts every identical block of data the same way, so patterns from the original often show through in the encrypted version.",
    "sha1": "Same story as MD5, just a bit newer. SHA-1 was proven breakable in 2017.",
    "rsa": "RSA key generation. It's fine against today's computers, but a large enough quantum computer could break it directly.",
    "ecdsa": "ECDSA signing. Holds up fine right now, but becomes breakable once quantum computers reach a certain scale.",
    "dh": "A Diffie-Hellman exchange. Secure against classical computers, but not against a sufficiently powerful quantum one.",
}
# How an attacker actually exploits each one, written so someone with zero
# security background still gets the real danger.
HOW_IT_BREAKS = {
    "hardcoded_key": "If this code ever goes public, the secret is just sitting there. Anyone can copy it and use it, no cracking involved.",
    "md5": "An attacker builds a second file that hashes to the same MD5 value as the original, so a tampered file slips past whatever check relied on it.",
    "ecb_mode": "Encrypt something like an image with ECB and you can often still make out its shape in the ciphertext, since identical blocks always encrypt the same way.",
    "sha1": "Same trick as MD5: craft a second file with a matching SHA-1 hash and the check gets fooled.",
    "rsa": "Once a quantum computer is big enough, Shor's algorithm lets it pull the private key straight out of the public key.",
    "ecdsa": "Same mechanism as RSA. A large enough quantum computer runs Shor's algorithm and derives the private key, letting it forge signatures.",
    "dh": "Shor's algorithm again, this time recovering the shared secret directly, which defeats the whole point of the exchange.",
}
