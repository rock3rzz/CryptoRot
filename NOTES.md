# CryptoRot Phase 2, verification notes

## Run it yourself
    python3 cli.py test_samples
    git clone https://github.com/sybrenstuvel/python-rsa.git   && python3 cli.py python-rsa
    git clone https://github.com/tlsfuzzer/python-ecdsa.git    && python3 cli.py python-ecdsa
    git clone https://github.com/mpdavis/python-jose.git       && python3 cli.py python-jose

## Repositories scanned (Python-compatible subset of Shaw 2026's 5-repo corpus)
- github.com/sybrenstuvel/python-rsa   (30 files, 4852 lines) -> 12 findings, 0.044s
- github.com/tlsfuzzer/python-ecdsa    (34 files, 20395 lines) -> 62 findings, 0.184s
- github.com/mpdavis/python-jose       (38 files, 6409 lines) -> 35 findings, 0.058s
Total: 109 findings. All 54 hardcoded_key findings checked by hand, see
real_scan_results/hardcoded_key_triage.json (one label per finding:
real_key_fixture / jwt_test_fixture / header_stub_only).

## Two bugs found and fixed during this testing
1. False positive: rsa/cli.py's keyname = "public"/"private" class attributes
   were flagged as hardcoded secrets (6-char length threshold). Fixed by
   raising the threshold to 12 characters. Re-checked: zero regressions on
   test_samples, both real PEM fixtures in python-rsa's tests still flagged.
2. Detection gap: python-ecdsa returned zero quantum-vulnerable findings on
   the first run, which made no sense for a library whose whole job is
   ECDSA. Root cause: the rule table only matched cryptography's
   ec.generate_private_key and pycryptodome's ECC.generate; python-ecdsa's
   own API is SigningKey.generate() (confirmed in src/ecdsa/keys.py, class
   SigningKey, def generate at line 810; real call site at
   src/ecdsa/ecdh.py line 123). Fixed by adding "SigningKey.generate":
   "ecdsa" to CALL_PATTERNS. Findings went from 0 to 41.

## Known limitations (documented, not hidden)
- 22 of 54 hardcoded_key findings are JWT test-token strings assigned to
  token-named variables, structurally identical to a real hardcoded bearer
  token at the AST level.
- 5 of 54 are PEM header fragments or malformed JSON used only to test
  error-handling code, no real key material.
- Only Python is implemented. Java and JavaScript are Phase 3 scope.
