"""
CryptoRot self-test: mutation testing of the scanner itself.

Studies of crypto-misuse detectors (Ami et al., "Why Crypto-detectors
Fail", MASC) found that detectors miss most often not because the rule is
absent but because the misuse is written a little differently from the
textbook example. This module attacks CryptoRot the same way: each seed is
a known misuse, and each operator rewrites it in a way real code does.

Each mutant ends in one of three states:
    detected   the scanner reported the expected finding
    declared   the scanner could not resolve it and said so (a blind spot)
    missed     silence: the dangerous outcome, and the one we drive to zero

Negative controls check the opposite failure, a finding on safe code.
"""

import os
import shutil
import tempfile

HASH_NEW_OPS = {}


def _mut(mid, family, op, code, expect, mode="detect", note=""):
    return {"id": mid, "family": family, "operator": op, "code": code.strip("\n") + "\n",
            "expect": expect, "mode": mode, "note": note}


def build():
    out = []

    # ---- hash called by function name -------------------------------------
    for prim, fn in (("md5", "md5"), ("sha1", "sha1")):
        fam = f"{fn} call"
        out += [
            _mut(f"{fn}-verbatim", fam, "verbatim", f"import hashlib\nh = hashlib.{fn}(b'x').hexdigest()", prim),
            _mut(f"{fn}-alias", fam, "module alias", f"import hashlib as hl\nh = hl.{fn}(b'x').hexdigest()", prim),
            _mut(f"{fn}-from", fam, "from-import", f"from hashlib import {fn}\nh = {fn}(b'x').hexdigest()", prim),
            _mut(f"{fn}-from-alias", fam, "from-import alias", f"from hashlib import {fn} as digest_fn\nh = digest_fn(b'x').hexdigest()", prim),
            _mut(f"{fn}-lambda", fam, "lambda wrapper", f"import hashlib\nhasher = lambda d: hashlib.{fn}(d)\nh = hasher(b'x')", prim),
            _mut(f"{fn}-nested", fam, "nested function", f"import hashlib\n\ndef outer():\n    def inner(d):\n        return hashlib.{fn}(d).digest()\n    return inner(b'x')", prim),
            _mut(f"{fn}-wrapped", fam, "wrapped lines", f"import hashlib\nh = (\n    hashlib\n    .{fn}(\n        b'x'\n    )\n    .hexdigest()\n)", prim),
            _mut(f"{fn}-cond", fam, "inside condition", f"import hashlib\nimport sys\nif sys.argv:\n    h = hashlib.{fn}(b'x')", prim),
            _mut(f"{fn}-class", fam, "inside method", f"import hashlib\n\nclass Store:\n    def key(self, d):\n        return hashlib.{fn}(d).hexdigest()", prim),
            _mut(f"{fn}-star", fam, "star import", f"from hashlib import *\nh = {fn}(b'x')", prim, "declare_ok",
                 "name comes from a star import; a blind spot must be reported"),
        ]

    # ---- hash chosen by name (hashlib.new) --------------------------------
    for prim, nm in (("md5", "md5"), ("sha1", "sha1")):
        fam = f"{nm} by name"
        cut = nm[:2]
        rest = nm[2:]
        up = nm.upper()
        out += [
            _mut(f"{nm}-new", fam, "string literal", f"import hashlib\nh = hashlib.new('{nm}', b'x')", prim),
            _mut(f"{nm}-new-var", fam, "variable holds name", f"import hashlib\nALGO = '{nm}'\nh = hashlib.new(ALGO, b'x')", prim),
            _mut(f"{nm}-new-concat", fam, "concatenated name", f"import hashlib\nh = hashlib.new('{cut}' + '{rest}', b'x')", prim),
            _mut(f"{nm}-new-fstr", fam, "f-string name", f"import hashlib\nn = '{nm[-1]}'\nh = hashlib.new(f'{nm[:-1]}{{n}}', b'x')", prim),
            _mut(f"{nm}-new-lower", fam, "case changed", f"import hashlib\nh = hashlib.new('{up}'.lower(), b'x')", prim),
            _mut(f"{nm}-new-kw", fam, "keyword argument", f"import hashlib\nh = hashlib.new(name='{nm}', data=b'x')", prim),
            _mut(f"{nm}-getattr", fam, "getattr lookup", f"import hashlib\nh = getattr(hashlib, '{nm}')(b'x')", prim),
            _mut(f"{nm}-param", fam, "passed through helper", f"import hashlib\n\ndef digest(algo, d):\n    return hashlib.new(algo, d)\n\nh = digest('{nm}', b'x')", prim),
            _mut(f"{nm}-default", fam, "helper default", f"import hashlib\n\ndef digest(d, algo='{nm}'):\n    return hashlib.new(algo, d)\n\nh = digest(b'x')", prim),
            _mut(f"{nm}-dict", fam, "dict lookup", f"import hashlib\nTABLE = {{'weak': '{nm}', 'ok': 'sha256'}}\nh = hashlib.new(TABLE['weak'], b'x')", prim),
            _mut(f"{nm}-from-new", fam, "from-import of new", f"from hashlib import new as mk\nh = mk('{nm}', b'x')", prim),
            _mut(f"{nm}-env", fam, "name from environment", f"import hashlib, os\nh = hashlib.new(os.environ['ALGO'], b'x')", prim, "declare_ok",
                 "name is only known at runtime; a blind spot must be reported"),
        ]

    # ---- ECB --------------------------------------------------------------
    out += [
        _mut("ecb-verbatim", "ecb mode", "verbatim", "from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_ECB)", "ecb_mode"),
        _mut("ecb-module-alias", "ecb mode", "module alias", "from Crypto.Cipher import AES as A\nc = A.new(k, A.MODE_ECB)", "ecb_mode"),
        _mut("ecb-var", "ecb mode", "mode in variable", "from Crypto.Cipher import AES\nMODE = AES.MODE_ECB\nc = AES.new(k, MODE)", "ecb_mode"),
        _mut("ecb-cryptography", "ecb mode", "cryptography API", "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nc = Cipher(algorithms.AES(k), modes.ECB())", "ecb_mode"),
        _mut("ecb-full-path", "ecb mode", "fully dotted", "import Crypto.Cipher.AES\nc = Crypto.Cipher.AES.new(k, Crypto.Cipher.AES.MODE_ECB)", "ecb_mode"),
        _mut("ecb-des", "ecb mode", "other cipher", "from Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_ECB)", "ecb_mode"),
    ]

    # ---- RSA --------------------------------------------------------------
    out += [
        _mut("rsa-verbatim", "rsa key", "verbatim", "import rsa\npub, priv = rsa.newkeys(2048)", "rsa"),
        _mut("rsa-from", "rsa key", "from-import", "from rsa import newkeys\npub, priv = newkeys(2048)", "rsa"),
        _mut("rsa-alias", "rsa key", "module alias", "import rsa as r\npub, priv = r.newkeys(2048)", "rsa"),
        _mut("rsa-pycrypto", "rsa key", "pycryptodome", "from Crypto.PublicKey import RSA\nk = RSA.generate(2048)", "rsa"),
        _mut("rsa-cryptography", "rsa key", "cryptography", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "rsa"),
        _mut("rsa-cryptography-alias", "rsa key", "cryptography alias", "from cryptography.hazmat.primitives.asymmetric import rsa as R\nk = R.generate_private_key(65537, 2048)", "rsa"),
        _mut("rsa-small", "rsa size", "literal 1024", "import rsa\npub, priv = rsa.newkeys(1024)", "weak_key"),
        _mut("rsa-small-var", "rsa size", "size in variable", "import rsa\nBITS = 1024\npub, priv = rsa.newkeys(BITS)", "weak_key"),
        _mut("rsa-small-arith", "rsa size", "arithmetic", "import rsa\npub, priv = rsa.newkeys(512 * 2)", "weak_key"),
        _mut("rsa-small-kw", "rsa size", "keyword", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=1024)", "weak_key"),
        _mut("rsa-small-param", "rsa size", "through helper", "import rsa\n\ndef make(bits):\n    return rsa.newkeys(bits)\n\nmake(1024)", "weak_key"),
        _mut("rsa-size-runtime", "rsa size", "size from user", "import rsa, sys\npub, priv = rsa.newkeys(int(sys.argv[1]))", "weak_key", "declare_ok",
             "size is only known at runtime; a blind spot must be reported"),
    ]

    # ---- EC / DH ----------------------------------------------------------
    out += [
        _mut("ec-ecdsa", "elliptic curve", "python-ecdsa", "from ecdsa import SigningKey, NIST256p\nsk = SigningKey.generate(curve=NIST256p)", "ecdsa"),
        _mut("ec-ecdsa-alias", "elliptic curve", "module alias", "import ecdsa as e\nsk = e.SigningKey.generate(curve=e.NIST256p)", "ecdsa"),
        _mut("ec-cryptography", "elliptic curve", "cryptography", "from cryptography.hazmat.primitives.asymmetric import ec\nk = ec.generate_private_key(ec.SECP256R1())", "ecdsa"),
        _mut("ec-cryptography-alias", "elliptic curve", "alias", "from cryptography.hazmat.primitives.asymmetric import ec as curves\nk = curves.generate_private_key(curves.SECP256R1())", "ecdsa"),
        _mut("ec-pycrypto", "elliptic curve", "pycryptodome", "from Crypto.PublicKey import ECC\nk = ECC.generate(curve='P-256')", "ecdsa"),
        _mut("ec-weak-curve", "elliptic curve", "192-bit curve", "from ecdsa import SigningKey, NIST192p\nsk = SigningKey.generate(curve=NIST192p)", "weak_key"),
        _mut("ec-x25519", "elliptic curve", "X25519 key agreement", "from cryptography.hazmat.primitives.asymmetric import x25519\nk = x25519.X25519PrivateKey.generate()", "ecdh"),
        _mut("dh-verbatim", "diffie-hellman", "verbatim", "from cryptography.hazmat.primitives.asymmetric import dh\np = dh.generate_parameters(generator=2, key_size=2048)", "dh"),
        _mut("dh-alias", "diffie-hellman", "alias", "from cryptography.hazmat.primitives.asymmetric import dh as D\np = D.generate_parameters(generator=2, key_size=2048)", "dh"),
    ]

    # ---- hardcoded keys ---------------------------------------------------
    out += [
        _mut("key-aes-literal", "hardcoded key", "literal at sink", "from Crypto.Cipher import AES\nc = AES.new(b'0123456789abcdef', AES.MODE_GCM)", "hardcoded_key"),
        _mut("key-aes-var", "hardcoded key", "variable at sink", "from Crypto.Cipher import AES\nSECRET = b'0123456789abcdef'\nc = AES.new(SECRET, AES.MODE_GCM)", "hardcoded_key"),
        _mut("key-aes-neutral-name", "hardcoded key", "neutral variable name", "from Crypto.Cipher import AES\nblob = b'0123456789abcdef'\nc = AES.new(blob, AES.MODE_GCM)", "hardcoded_key"),
        _mut("key-aes-concat", "hardcoded key", "split literal", "from Crypto.Cipher import AES\nc = AES.new(b'01234567' + b'89abcdef', AES.MODE_GCM)", "hardcoded_key"),
        _mut("key-hmac", "hardcoded key", "hmac key", "import hmac, hashlib\nm = hmac.new(b'supersecretvalue', b'msg', hashlib.sha256)", "hardcoded_key"),
        _mut("key-hmac-alias", "hardcoded key", "hmac alias", "import hmac as hm, hashlib\nm = hm.new(b'supersecretvalue', b'msg', hashlib.sha256)", "hardcoded_key"),
        _mut("key-jwt", "hardcoded key", "jwt signing secret", "from jose import jwt\nt = jwt.encode({'a': 1}, 'my-long-signing-secret', algorithm='HS256')", "hardcoded_key"),
        _mut("key-jwt-kw", "hardcoded key", "jwt keyword", "from jose import jwt\nt = jwt.encode({'a': 1}, key='my-long-signing-secret', algorithm='HS256')", "hardcoded_key"),
        _mut("key-fernet", "hardcoded key", "fernet", "from cryptography.fernet import Fernet\nf = Fernet(b'0123456789abcdef0123456789abcdef0123456789a=')", "hardcoded_key"),
        _mut("key-name-hint", "hardcoded key", "assignment by name", "API_KEY = 'sk_live_51H8abcdefghijkl'", "hardcoded_key"),
        _mut("key-annotated", "hardcoded key", "annotated assignment", "API_KEY: str = 'sk_live_51H8abcdefghijkl'", "hardcoded_key"),
    ]

    # ---- negative controls: must NOT be reported as debt -------------------
    neg = [
        ("neg-sha256", "hashlib.sha256 is fine", "import hashlib\nh = hashlib.sha256(b'x')", ("md5", "sha1")),
        ("neg-comment", "md5 only in a comment", "import hashlib\n# do not use hashlib.md5 here\nh = hashlib.sha256(b'x')", ("md5",)),
        ("neg-string", "md5 only in a string", "msg = 'we replaced hashlib.md5 with sha256'\nprint(msg)", ("md5",)),
        ("neg-varname", "md5 only as a name", "md5 = 'abc'\nsha1_label = 'x'\nprint(md5, sha1_label)", ("md5", "sha1")),
        ("neg-docstring", "md5 only in a docstring", "def f():\n    '''Legacy code used hashlib.sha1(data).'''\n    return 1", ("sha1",)),
        ("neg-short-key", "short non-secret string", "keyname = 'public'", ("hardcoded_key",)),
        ("neg-env-key", "key from environment", "import os\nfrom Crypto.Cipher import AES\nc = AES.new(os.environ['K'].encode(), AES.MODE_GCM)", ("hardcoded_key",)),
        ("neg-big-rsa", "RSA 3072 is not undersized", "import rsa\npub, priv = rsa.newkeys(3072)", ("weak_key",)),
        ("neg-gcm", "GCM is not ECB", "from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_GCM)", ("ecb_mode",)),
    ]
    for mid, note, code, forbidden in neg:
        out.append(_mut(mid, "negative control", "safe code", code, forbidden, "negative", note))
    out.append(_mut("neg-benign-md5", "negative control", "usedforsecurity=False",
                    "import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)", ("md5",), "benign",
                    "reported for the inventory but classed as non-security, not debt"))
    return out


def evaluate(scan_fn):
    """scan_fn(dir) -> (findings, blind_spots) with .primitive/.benign attributes.
    Returns (rows, summary)."""
    rows = []
    for m in build():
        d = tempfile.mkdtemp(prefix="crst_")
        try:
            with open(os.path.join(d, "case.py"), "w") as f:
                f.write(m["code"])
            findings, blind = scan_fn(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        prims = {f.primitive for f in findings}
        if m["mode"] == "negative":
            bad = [p for p in m["expect"] if p in prims]
            state = "pass" if not bad else "false-positive"
        elif m["mode"] == "benign":
            hit = [f for f in findings if f.primitive in m["expect"]]
            state = "pass" if hit and all(getattr(f, "benign", False) for f in hit) else \
                    ("false-positive" if hit else "pass")
        else:
            if m["expect"] in prims:
                state = "detected"
            elif blind:
                state = "declared"
            else:
                state = "missed"
        rows.append({"id": m["id"], "family": m["family"], "operator": m["operator"],
                     "mode": m["mode"], "state": state, "note": m["note"], "code": m["code"]})
    pos = [r for r in rows if r["mode"] in ("detect", "declare_ok")]
    neg = [r for r in rows if r["mode"] in ("negative", "benign")]
    summary = {
        "mutants": len(pos),
        "detected": sum(r["state"] == "detected" for r in pos),
        "declared": sum(r["state"] == "declared" for r in pos),
        "missed": sum(r["state"] == "missed" for r in pos),
        "controls": len(neg),
        "false_positives": sum(r["state"] == "false-positive" for r in neg),
    }
    summary["silent_miss_rate"] = round(summary["missed"] / summary["mutants"], 4) if summary["mutants"] else 0
    summary["detect_rate"] = round(summary["detected"] / summary["mutants"], 4) if summary["mutants"] else 0
    return rows, summary


def scan_v04(d):
    from ast_scanner import scan_directory
    f, b, _ = scan_directory(d)
    return f, b


if __name__ == "__main__":
    import json
    rows, s = evaluate(scan_v04)
    print(json.dumps(s, indent=2))
    for r in rows:
        if r["state"] in ("missed", "false-positive"):
            print(r["state"], r["id"], "|", r["operator"])
