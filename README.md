# CryptoRot, Phase 2 scanner

Four modules: rules.py (severity table), ast_scanner.py (AST walker),
scorer.py (debt formula), cli.py (orchestration).

Run: python3 cli.py <path-to-repo> [output.json]

See NOTES.md for the full verification log, the two bugs found and fixed
during real-repo testing, and known limitations. real_scan_results/ has
the actual saved output from scanning python-rsa, python-ecdsa, and
python-jose, plus the combined dataset and the triage labels for every
hardcoded-key finding.
