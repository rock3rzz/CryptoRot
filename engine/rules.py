"""
CryptoRot rule tables, v0.4.

Detection tables only. Everything that says how bad a finding is (clock,
deadline, standard) lives in model.py with a citation next to it.

Matching is done on two names for every call: the literal dotted name as
written in the source (v0.3 behaviour, kept so nothing the old engine
found can disappear) and the import-resolved name (new in v0.4), so
`from hashlib import md5 as h; h(x)` is the same finding as hashlib.md5(x).
"""

# Dotted call-name patterns that map directly to a primitive. Compared
# against the literal name, the import-resolved name, and every suffix of
# the resolved name that keeps at least two segments.
CALL_PATTERNS = {
    # --- v0.3 patterns, unchanged -------------------------------------
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
    # --- v0.4 additions: same primitives, other spellings --------------
    "Cryptodome.Hash.MD5.new": "md5",
    "Cryptodome.Hash.SHA1.new": "sha1",
    "hashes.MD5": "md5",
    "hashes.SHA1": "sha1",
    "Cryptodome.PublicKey.RSA.generate": "rsa",
    "Cryptodome.PublicKey.ECC.generate": "ecdsa",
    "ec.derive_private_key": "ecdsa",
    "dh.generate_private_key": "dh",
    "x25519.X25519PrivateKey.generate": "ecdh",
    "ed25519.Ed25519PrivateKey.generate": "ecdsa",
    "ed448.Ed448PrivateKey.generate": "ecdsa",
    "x448.X448PrivateKey.generate": "ecdh",
}

# covers hashlib.new("md5", ...) where the algorithm is the first argument
HASHLIB_NEW_ALGOS = {"md5": "md5", "sha1": "sha1", "sha-1": "sha1",
                     "ssl3-md5": "md5", "ssl3-sha1": "sha1"}

# Any attribute access ending in one of these names flags ECB mode
ECB_ATTR_SUFFIXES = {"MODE_ECB"}
# cryptography.hazmat modes.ECB() call
ECB_CALL_PATTERNS = {"modes.ECB"}

# Variable-name fragments that mark an assignment as a candidate hardcoded
# secret (case-insensitive substring match). v0.3 rule, unchanged.
SECRET_NAME_HINTS = ("key", "secret", "password", "passwd", "token", "api_key")
SECRET_MIN_LEN = 12

# Calls whose argument IS a secret key. A literal reaching one of these is a
# proven hardcoded key. value: (positional index, keyword name)
KEY_SINKS = {
    "hmac.new": (0, "key"),
    "AES.new": (0, "key"),
    "DES.new": (0, "key"),
    "DES3.new": (0, "key"),
    "ChaCha20.new": (None, "key"),
    "Fernet": (0, "key"),
    "fernet.Fernet": (0, "key"),
    "jwt.encode": (1, "key"),
    "jwt.decode": (1, "key"),
    "jws.sign": (1, "key"),
    "jws.verify": (1, "key"),
}
KEY_SINK_MIN_LEN = 8

# Weak-parameter extraction: where the key size lives. value: (index, kw)
RSA_SIZE_ARG = {
    "rsa.newkeys": (0, "nbits"),
    "RSA.generate": (0, "bits"),
    "Cryptodome.PublicKey.RSA.generate": (0, "bits"),
    "rsa.generate_private_key": (1, "key_size"),
}
# curve argument for EC key generation. value: (index, kw)
EC_CURVE_ARG = {
    "ec.generate_private_key": (0, "curve"),
    "SigningKey.generate": (None, "curve"),
    "ECC.generate": (None, "curve"),
}

# Identifier vocabulary used to infer what a file *does* with a primitive
ENC_WORDS = ("encrypt", "decrypt", "oaep", "encapsul", "decapsul")
KEX_WORDS = ("ecdh", "exchange", "diffie", "key_agree", "keyagree", "derive_shared")
SIG_WORDS = ("sign", "verify", "signature", "signing")
PWD_WORDS = ("password", "passwd", "pwhash", "pbkdf", "bcrypt")
INTEGRITY_WORDS = ("checksum", "fingerprint", "etag", "cache", "digest", "hexdigest")

TEST_FILE_PREFIXES = ("test_", "tests_", "conftest")
TEST_DIRS = ("test", "tests", "testing", "spec", "specs", "mock", "mocks",
             "fixtures", "examples", "example", "docs", "doc")
