<p align="center"><img src="docs/images/00-banner.png" alt="CryptoRot" width="100%"></p>

CryptoRot is a static analyzer for Python that finds weak or soon-to-be-retired cryptography and puts each finding on a calendar. Every finding gets a due year and a cited source, not a score.

Organizations moving to post-quantum cryptography start with an inventory of where crypto lives in their code. CryptoRot builds that inventory from the AST, exports it as a CycloneDX CBOM, and shows how much of it will need to change, and when.

<p align="center"><img src="docs/images/01-scan.png" width="49%"> <img src="docs/images/02-proof.png" width="49%"></p>
<p align="center"><img src="docs/images/03-dates.png" width="49%"> <img src="docs/images/08-deadlines.png" width="49%"></p>

## What it does

- Resolves calls through the Python `ast`: import aliases, constant folding, keyword arguments, `getattr`, and one-hop parameter propagation.
- Flags weak hashes, ECB mode, hardcoded keys, short RSA/EC keys, and quantum-vulnerable public-key use.
- Reports three clocks per finding: now, policy (2030), and quantum (2031 to 2035).
- Separates harvest-now-decrypt-later exposure from forgery-later exposure.
- Labels each finding proven, probable or heuristic, and tags it source, test or example.
- Declares its blind spots instead of hiding them.
- Exports JSON, CycloneDX 1.6 CBOM, SARIF 2.1.0 and CSV.

<p align="center"><img src="docs/images/04-harvest.png" width="49%"> <img src="docs/images/05-label.png" width="49%"></p>

## Run it

```
python3 engine/cli.py path/to/project
```

The dashboard talks to a scan service (`server/`) that runs the engine. The page itself ships no rules or scoring. Set `CR_API` to the service URL when building the page.

```
CR_API=https://your-service python3 web/build.py   # writes public/index.html
uvicorn app:app --app-dir server               # run the service
```

`public/` is a static site and deploys as is (`vercel.json` is included).

## Benchmark

A finding is one line of code that uses a broken or expiring hash, cipher or key, for example `hashlib.md5(data)` or `rsa.generate_private_key(...)`.

**Round 1.** 20 open-source Python projects, pinned by commit SHA in `bench/pins.json`: 5,604 files, 1,197,921 lines, 1,017 findings. 52 of the findings in shipped code were labelled by reading the code around each one: 31 real, 20 false alarms, 1 unsure. Precision is 61%.

**Round 2.** 20 more projects that no rule was tuned on, pinned in `bench/pins2.json`: 7,237 files, 1.8 million lines, 294 findings, 91 of them in shipped code. Chosen by a stated rule (GitHub topic `security`, Python, over 1,500 stars, pushed after 15 Oct 2026, taken in star order). The 91 were labelled the same way: 53 real, 36 false alarms, 2 borderline. Precision is 60%.

- Real means the program genuinely uses MD5, SHA-1, ECB mode, a hardcoded key, or an RSA or elliptic-curve key that a quantum computer will break.
- A false alarm is something like an MD5 used only to build a cache key or an ID.
- Every label and the reason for it is in `bench/labels2.json`, so any of them can be disputed.

The first 12 projects of round 1 scored 75%. The 8 added later pulled it down: hash lookup tables, cache keys and protocol-mandated checksums are flagged as weak hashes although they carry no security weight. Round 2 shows the same pattern, which makes it the next rule to tighten.

<p align="center"><img src="docs/images/06-bench.png" width="49%"> <img src="docs/images/07-selftest.png" width="49%"></p>

### Against other scanners

The same round 2 checkouts were scanned with Bandit 1.9.4, Semgrep 1.184.0 (registry rules `p/python`) and CodeQL (`python-security-extended`), all on 9 November 2026.

| | CryptoRot | Bandit | Semgrep | CodeQL |
|---|---|---|---|---|
| Real weak-crypto lines found, of 59 known | 53 | 26 | 25 | 6 |
| RSA, elliptic-curve and Diffie-Hellman keys found, of 29 | 29 | 0 | 0 | 1 |
| Weakness hidden 82 ways: found | 77 found, 5 reported as unable to tell, 0 silent misses | 26 | 30 | 4 |
| Share of its flags on labelled lines that were real | 60% (53 of 89) | 47% (22 of 47) | 43% (20 of 47) | 75% (6 of 8) |
| Says when it cannot tell | yes, with file and line | no | no | no |
| Due year and cited standard per finding | yes | no | no | no |
| Output | JSON, CBOM 1.6, SARIF 2.1.0 | csv, html, json, txt, xml, yaml | JSON, SARIF | SARIF, CSV |

The 59 known real lines are CryptoRot's 53 plus 6 weak ciphers that Bandit and Semgrep found and CryptoRot has no rule for yet: MD4 (2), RC4 (2) and 3DES (2). The 53 start from CryptoRot's own output, so this table cannot show what all four tools missed. IBM CBOMkit (the Sonar Cryptography plugin) was compared from its documentation only, since it runs inside a SonarQube server.

The 82 rewrites are the self-test described below. Each is a known weak primitive written the way real code varies it: an aliased import, the word `md5` built from two strings, an algorithm passed through a helper. They were written by the author of CryptoRot, so they show what each tool can follow and not how often real code is written that way.

Self-test: 82 mutant programs with known weak crypto plus 10 negative controls. Version 0.3 detected 27. Version 0.4 detects 77, declares 5 as blind spots, misses none, and raises no false positives on the controls.

Reproduce:

```
bench/fetch.sh
python3 bench/make_data.py && python3 bench/make_reviews.py
python3 engine/selftest.py

bench/fetch2.sh                # round 2 checkouts
python3 bench/round2.py        # needs bandit and semgrep installed
```

## Privacy

The hosted scanner receives the source you send, scans it in a temporary directory and deletes it when the request ends. Request bodies are never written to disk or logs. The rate limiter keeps your IP address in memory for 1 hour. For code that cannot leave your machine, use the command-line version.

## Limits

- No rules yet for MD4, RC4 or 3DES. Round 2 found 6 of them that Bandit and Semgrep reported and CryptoRot did not.
- About 4 in 10 findings in shipped code are false alarms (60% precision in round 2, 61% in round 1).
- One person labelled all findings, and that person also wrote the scanner. A second labeller is still to do, with agreement reported as Cohen's kappa.
- The self-test mutants were written by the project's author and are disclosed as such.
- Round 2 projects are security tools, which use cryptography more than most code, so counts there run higher than they would on a random project.
- Reachability is name-based.
- Python only, and static analysis cannot see keys or algorithms chosen at runtime.

## Layout

```
engine/   scanner, rules, exporters, self-test, CLI
web/      dashboard source and build script
bench/    pinned projects, labels, data and head-to-head scripts
docs/     README images
public/   built static site
```

## Contact

rk, High Energy Digital.

## License

Copyright (c) 2026 rk. All rights reserved. No permission is granted to use, copy, modify or distribute this code without written consent.
