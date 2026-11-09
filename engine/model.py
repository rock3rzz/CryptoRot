"""
CryptoRot threat model, v0.4.

This replaces the v0.3 base x path x frequency formula. There is no blended
score any more. Every finding is placed on one of four clocks, and each
clock is defined by a dated standard that is cited here, next to the rule:

    now      practical attack or outright prohibition in force today
    policy   a standards body has set a dated phase-out
    quantum  broken by Shor's algorithm once a large quantum computer exists
    benign   the code itself declares a non-security use

The output of the model is a due year and a reason, not a number between
0 and 100. If a date below is wrong, the fix is one line and one source.
"""

# id -> (title, url). url is None when only the document number is known.
SOURCES = {
    "RFC6151": ("RFC 6151: Updated security considerations for MD5", "https://www.rfc-editor.org/rfc/rfc6151"),
    "RFC9155": ("RFC 9155: Deprecating MD5 and SHA-1 signature hashes in TLS 1.2 and DTLS 1.2", "https://www.rfc-editor.org/rfc/rfc9155"),
    "SHATTERED": ("Stevens et al. 2017: first SHA-1 collision", "https://shattered.io"),
    "NISTSHA1": ("NIST: SHA-1 retired, phase out by 31 Dec 2030", "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"),
    "SP800-38A": ("NIST SP 800-38A: block cipher modes (ECB leaks plaintext structure)", "https://csrc.nist.gov/pubs/sp/800/38/a/final"),
    "SP800-131A": ("NIST SP 800-131A Rev 2: transitioning cryptographic algorithms and key lengths", "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"),
    "SP800-57": ("NIST SP 800-57 Part 1 Rev 5: key management, security strengths", "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final"),
    "CWE321": ("CWE-321: use of hard-coded cryptographic key", "https://cwe.mitre.org/data/definitions/321.html"),
    "CWE327": ("CWE-327: use of a broken or risky cryptographic algorithm", "https://cwe.mitre.org/data/definitions/327.html"),
    "CWE326": ("CWE-326: inadequate encryption strength", "https://cwe.mitre.org/data/definitions/326.html"),
    "IR8547": ("NIST IR 8547: transition to post-quantum cryptography standards (deprecated after 2030, disallowed after 2035)", "https://csrc.nist.gov/pubs/ir/8547/final"),
    "EO14412": ("EO 14412 / OMB M-26-15: federal high-value assets, key establishment 2030, signatures 2031", None),
    "NSM10": ("NSM-10: national security systems migrate by 2035", None),
    "CNSA2": ("NSA CNSA 2.0: software and firmware signing exclusive by 2030, web/cloud/OS by 2033", "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"),
    "FIPS203": ("FIPS 203: ML-KEM", "https://csrc.nist.gov/pubs/fips/203/final"),
    "FIPS204": ("FIPS 204: ML-DSA", "https://csrc.nist.gov/pubs/fips/204/final"),
    "FIPS205": ("FIPS 205: SLH-DSA", "https://csrc.nist.gov/pubs/fips/205/final"),
    "SP800-208": ("NIST SP 800-208: LMS and XMSS stateful hash-based signatures", "https://csrc.nist.gov/pubs/sp/800/208/final"),
    "MOSCA": ("Mosca 2018: cybersecurity in an era with quantum computers", None),
    "GIDNEY25": ("Gidney 2025: RSA-2048 with fewer than a million noisy qubits", "https://arxiv.org/abs/2505.15917"),
}

# Years the model is anchored on. Both come from the sources above.
QUANTUM_DEPRECATE_AFTER = 2030   # IR8547
QUANTUM_DISALLOW_AFTER = 2035    # IR8547, NSM10
SHA1_PHASEOUT = 2030             # NISTSHA1

# primitive id -> definition
PRIMS = {
    "md5": dict(
        title="MD5 hash", clock="now", cls="classical", family="hash",
        why=("MD5 collisions take seconds on a laptop, so an MD5 check can no longer detect tampering."),
        fix="Switch to SHA-256 or SHA-3. Hash passwords with Argon2id or scrypt.",
        sources=["RFC6151", "RFC9155", "CWE327"], cwe=["CWE-327"],
        cbom=dict(primitive="hash", classical=None, quantum=None)),
    "sha1": dict(
        title="SHA-1 hash", clock="policy", cls="classical", family="hash",
        why=("Researchers produced a SHA-1 collision in 2017. NIST ends its use on 31 Dec 2030, "
             "and signatures have been prohibited for longer."),
        fix="Switch to SHA-256 or SHA-3. Where a protocol requires SHA-1, pass usedforsecurity=False if the hash is only an identifier.",
        sources=["NISTSHA1", "SHATTERED", "RFC9155", "CWE327"], cwe=["CWE-327"],
        due=SHA1_PHASEOUT,
        cbom=dict(primitive="hash", classical=None, quantum=None)),
    "ecb_mode": dict(
        title="Block cipher in ECB mode", clock="now", cls="classical", family="mode",
        why=("ECB encrypts equal blocks of data to equal blocks of ciphertext. Patterns in the data "
             "stay visible, and an attacker can reorder blocks unnoticed."),
        fix="Use an authenticated mode such as AES-GCM or ChaCha20-Poly1305.",
        sources=["SP800-38A", "CWE327"], cwe=["CWE-327"],
        cbom=dict(primitive="block-cipher", classical=None, quantum=None)),
    "hardcoded_key": dict(
        title="Hardcoded key or secret", clock="now", cls="classical", family="key",
        why=("A key written in the source is readable by everyone who can read the repository or the package."),
        fix="Load keys from the environment or a secrets manager, and rotate the exposed value.",
        sources=["CWE321"], cwe=["CWE-321", "CWE-798"],
        cbom=dict(primitive="key", classical=None, quantum=None)),
    "weak_key": dict(
        title="Undersized key or curve", clock="now", cls="classical", family="param",
        why=("The key gives under 112 bits of security, the floor NIST sets. A classical computer can break it."),
        fix="Use RSA of at least 2048 bits (3072 preferred) or a curve of at least 224 bits (P-256 preferred).",
        sources=["SP800-131A", "SP800-57", "CWE326"], cwe=["CWE-326"],
        cbom=dict(primitive="pke", classical=None, quantum=0)),
    "rsa": dict(
        title="RSA", clock="quantum", cls="quantum", family="pk",
        why=("RSA depends on factoring, and Shor's algorithm factors on a large quantum computer. "
             "Today's computers cannot break it. NIST deprecates it after 2030."),
        sources=["IR8547", "EO14412", "NSM10", "GIDNEY25", "MOSCA"], cwe=[],
        cbom=dict(primitive="pke", classical="rsa", quantum=0)),
    "ecdsa": dict(
        title="Elliptic-curve signature", clock="quantum", cls="quantum", family="pk",
        why=("Elliptic-curve signatures depend on the discrete logarithm problem, which Shor's algorithm "
             "solves on a large quantum computer."),
        sources=["IR8547", "EO14412", "NSM10", "CNSA2", "MOSCA"], cwe=[],
        cbom=dict(primitive="signature", classical="ec", quantum=0)),
    "ecdh": dict(
        title="Elliptic-curve key agreement", clock="quantum", cls="quantum", family="pk",
        why=("ECDH and X25519 depend on the discrete logarithm problem, which Shor's algorithm solves on a "
             "quantum computer. Traffic recorded today can be opened later."),
        sources=["IR8547", "EO14412", "NSM10", "MOSCA"], cwe=[],
        cbom=dict(primitive="key-agree", classical="ec", quantum=0)),
    "dh": dict(
        title="Diffie-Hellman key exchange", clock="quantum", cls="quantum", family="pk",
        why=("Finite-field Diffie-Hellman depends on the discrete logarithm problem, which Shor's algorithm "
             "solves on a quantum computer. Traffic recorded today can be opened later."),
        sources=["IR8547", "EO14412", "NSM10", "MOSCA"], cwe=[],
        cbom=dict(primitive="key-agree", classical="ff", quantum=0)),
}

CLOCK_ORDER = {"now": 0, "policy": 1, "quantum": 2, "benign": 3}
CLOCK_LABEL = {
    "now": "Broken or prohibited today",
    "policy": "Standards deadline",
    "quantum": "Quantum-vulnerable",
    "benign": "Declared non-security",
}
CONF_ORDER = {"proven": 0, "probable": 1, "heuristic": 2}


def rsa_strength(bits):
    """Classical security strength in bits for an RSA modulus (SP 800-57)."""
    if bits >= 15360: return 256
    if bits >= 7680: return 192
    if bits >= 3072: return 128
    if bits >= 2048: return 112
    if bits >= 1024: return 80
    return None


def ec_strength(curve_bits):
    return curve_bits // 2 if curve_bits else None


def quantum_remedy(exposure, purpose):
    kex = ("ML-KEM (FIPS 203), in TLS as the hybrid X25519MLKEM768 so nothing "
           "breaks during the cutover")
    sig = ("ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for long-lived roots; "
           "for firmware and software signing use LMS or XMSS (SP 800-208)")
    if exposure == "harvest-now":
        return "Move to " + kex + "."
    if exposure == "forgery-future":
        return "Move to " + sig + "."
    return "Encryption and key exchange: " + kex + ". Signatures: " + sig + "."


def classify(prim, ctx):
    """Place a finding on a clock. ctx is a dict the scanner fills:
         purpose   set of {'enc','kex','sig','pwd','integrity'}
         benign    True if usedforsecurity=False was declared
         key_bits  int or None (RSA modulus)
         curve_bits int or None
    Returns a dict with clock, due, hard_stop, exposure, status, fix."""
    p = PRIMS[prim]
    clock = p["clock"]
    due = p.get("due")
    hard = None
    exposure = None
    status = ""
    fix = p.get("fix", "")
    purpose = ctx.get("purpose", set())

    if ctx.get("benign") and ctx.get("context") == "building-block":
        return dict(clock="benign", due=None, hard_stop=None, exposure=None,
                    status="This library implements cipher modes. GCM, SIV, XTS, CMAC and key wrap are built from the raw block cipher in ECB, so this call is part of the implementation.",
                    fix="No change needed. Confirm that no caller can pass it more than one block of user data.")
    if ctx.get("benign") and ctx.get("context") == "hybrid-pq":
        return dict(clock="benign", due=None, hard_stop=None, exposure=None,
                    status="Half of a hybrid key exchange with ML-KEM, the recommended transition design. Keep both halves until the standards settle.",
                    fix="No change needed. Follow the ML-KEM profile your protocol standardises on.")
    if ctx.get("benign"):
        return dict(clock="benign", due=None, hard_stop=None, exposure=None,
                    status="The code passes usedforsecurity=False, which declares a non-security use. Listed in the inventory and left out of the debt count.",
                    fix="No change needed. Keep the flag.")

    if clock == "now":
        status = {"md5": "Practical collisions exist today, and RFC 6151 and RFC 9155 prohibit it for signatures.",
                  "ecb_mode": "Leaks the structure of the plaintext today (SP 800-38A).",
                  "hardcoded_key": "Anyone with the source has the key today (CWE-321).",
                  "weak_key": "Below the 112-bit floor that SP 800-131A prohibits."}[prim]
        due = None
    elif clock == "policy":
        if ctx.get("context") == "collision-insensitive":
            status = ("NIST ends SHA-1 use on 31 Dec 2030. Here it sits inside OAEP, MGF1, HMAC or a key derivation function, "
                      "which stay safe against collisions, so no practical attack exists today.")
        else:
            status = ("NIST ends SHA-1 use on 31 Dec 2030. Collisions have been practical since 2017, so "
                      "SHA-1 in a signature, certificate or integrity check is already unsafe (RFC 9155).")
    elif clock == "quantum":
        if prim == "dh" or prim == "ecdh":
            exposure = "harvest-now"
        elif prim == "ecdsa":
            exposure = "forgery-future"
            if "kex" in purpose and "sig" not in purpose:
                exposure = "harvest-now"
        else:  # rsa: use what the file does with it
            if ("enc" in purpose or "kex" in purpose):
                exposure = "harvest-now"
            elif "sig" in purpose:
                exposure = "forgery-future"
            else:
                exposure = "unspecified"
        if exposure == "forgery-future":
            due = 2031
            status = ("A signature scheme. A future quantum computer could forge signatures, and recorded traffic carries no risk here. "
                      "Federal deadline for high-value assets: 2031.")
        elif exposure == "harvest-now":
            due = 2030
            status = ("Key establishment or encryption. Traffic recorded today can be decrypted later, so the exposure grows every day. "
                      "Federal deadline for high-value assets: 2030.")
        else:
            due = 2030
            status = ("The code does not show what this RSA key is for. RSA serves encryption (exposed to recorded traffic) "
                      "and signatures, so the earlier date applies.")
        hard = QUANTUM_DISALLOW_AFTER
        fix = quantum_remedy(exposure, purpose)
    return dict(clock=clock, due=due, hard_stop=hard, exposure=exposure, status=status, fix=fix)
