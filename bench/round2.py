"""Round 2 head-to-head. Runs CryptoRot, Bandit and Semgrep (p/python) on the 20 projects in pins2.json and on the
82 self-test rewrites, applies the hand labels in labels2.json and writes web/data/round2.json.
Run bench/fetch2.sh first, then from the repository root: python3 bench/round2.py
Set R2_OUT to reuse a directory of earlier tool output (<name>.cr.json, <name>.bandit.json, <name>.sg.json,
mut.bandit.json, mut.sg.json)."""
import collections, json, os, re, subprocess, sys, tempfile, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'engine')); os.chdir(ROOT)
import selftest, report
B = 'bench/'; pins = json.load(open(B + 'pins2.json')); labels = json.load(open(B + 'labels2.json')); missed = json.load(open(B + 'missed2.json'))
OUT = os.environ.get('R2_OUT') or tempfile.mkdtemp(prefix='r2_')
BANDIT_IDS = {'B303', 'B304', 'B305', 'B324'}
SG = re.compile(r'crypto|hash|cipher|md5|sha1|insecure-hash|ecb|des|rsa|blowfish|rc4', re.I)
def sh(c): subprocess.run(c, shell=True, capture_output=True)
def have(p): return os.path.exists(os.path.join(OUT, p))
for p in pins:
    n, d = p['name'], f"bench/repos2/{p['name']}"
    if not have(n + '.cr.json'): sh(f"python3 engine/cli.py {d} -q --no-color --tests -o {OUT}/{n}.cr.json")
    if not have(n + '.bandit.json'): sh(f"bandit -r {d} -f json -q -o {OUT}/{n}.bandit.json")
    if not have(n + '.sg.json'): sh(f"semgrep --config p/python --metrics=off --quiet --json -o {OUT}/{n}.sg.json {d}")
mut = tempfile.mkdtemp(prefix='mut_')
for m in selftest.build(): open(f"{mut}/{m['id']}.py", 'w').write(m['code'])
if not have('mut.bandit.json'): sh(f"bandit -r {mut} -f json -q -o {OUT}/mut.bandit.json")
if not have('mut.sg.json'): sh(f"semgrep --config p/python --metrics=off --quiet --json -o {OUT}/mut.sg.json {mut}")
J = lambda p: json.load(open(os.path.join(OUT, p)))
CQL = os.environ.get('CQL_OUT')   # directory of CodeQL SARIF: out_<name>.sarif and out_mut.sarif (python-security-extended suite)
def cql(name):
    p = os.path.join(CQL, f'out_{name}.sarif')
    if not (CQL and os.path.exists(p)): return None
    out = []
    for r in json.load(open(p))['runs'][0]['results']:
        if r['ruleId'].startswith(('py/weak-', 'py/insecure-default-protocol')) or 'hardcoded' in r['ruleId']:
            l = r['locations'][0]['physicalLocation']; out.append((l['artifactLocation']['uri'], l['region']['startLine'], r['ruleId']))
    return out
bhit, shit, crs, chit = {}, {}, {}, {}
repos = []
for p in pins:
    n = p['name']; cr, b, s = J(n + '.cr.json'), J(n + '.bandit.json'), J(n + '.sg.json')
    for r in b['results']:
        if r['test_id'] in BANDIT_IDS: bhit[(n, r['filename'].split(f'repos2/{n}/', 1)[-1].split(f'repos/{n}/', 1)[-1], r['line_number'])] = r['test_id']
    for r in s['results']:
        if SG.search(r['check_id']): shit[(n, r['path'].split(f'repos2/{n}/', 1)[-1].split(f'repos/{n}/', 1)[-1], r['start']['line'])] = r['check_id'].split('.')[-1]
    for f_, l_, r_ in (cql(n) or []): chit[(n, f_, l_)] = r_
    src = [f for f in cr['findings'] if f['scope'] == 'source']
    for f in cr['findings']: crs[(n, f['file'], f['line'])] = f
    repos.append(dict(name=n, url=p['url'], commit=p['commit'][:7], stars=p['stars'], files=cr['coverage']['files_parsed'], loc=cr['coverage']['loc'],
                      total=len(cr['findings']), shipped=len([f for f in src if f['clock'] != 'benign']), blind=len(cr['blind_spots']),
                      bandit=len([k for k in bhit if k[0] == n]), semgrep=len([k for k in shit if k[0] == n]), codeql=(len([k for k in chit if k[0] == n]) if cql(n) is not None else None)))
for m_ in missed:
    k = (m_['repo'], m_['file'], m_['line']); m_['bandit'] = k in bhit; m_['semgrep'] = k in shit; m_['codeql'] = k in chit
for l in labels:
    k = (l['repo'], l['file'], l['line']); l['bandit'] = k in bhit; l['semgrep'] = k in shit; l['codeql'] = k in chit
by = collections.defaultdict(lambda: collections.Counter())
for l in labels:
    c = by[l['clock']]; c['n'] += 1; c['bandit'] += l['bandit']; c['semgrep'] += l['semgrep']
real = [l for l in labels if l['label'] == 'real']; fal = [l for l in labels if l['label'] == 'false']; uns = [l for l in labels if l['label'] == 'unsure']
for r in repos:
    r['lab'] = {t: sum(1 for l in labels if l['repo'] == r['name'] and l['label'] == t) for t in ('real', 'false', 'unsure')}
# self-test rewrites
rows, s04 = selftest.evaluate(selftest.scan_v04)
st = {r['id']: r['state'] for r in rows}
mb, ms = J('mut.bandit.json')['results'], J('mut.sg.json')['results']
bf = {os.path.basename(r['filename'])[:-3] for r in mb if r['test_id'] in BANDIT_IDS | {'B105', 'B106', 'B107', 'B505'}}
sf = {os.path.basename(r['path'])[:-3] for r in ms}
cm = cql('mut'); cf = {os.path.basename(u)[:-3] for u, _, _ in (cm or [])}
fam = collections.OrderedDict(); pos = [m for m in selftest.build() if m['mode'] in ('detect', 'declare_ok')]; neg = [m for m in selftest.build() if m['mode'] in ('negative', 'benign')]
for m in pos:
    f = fam.setdefault(m['family'], dict(n=0, cryptorot=0, declared=0, bandit=0, semgrep=0))
    f['n'] += 1; f['cryptorot'] += st[m['id']] == 'detected'; f['declared'] += st[m['id']] == 'declared'; f['bandit'] += m['id'] in bf; f['semgrep'] += m['id'] in sf; f['codeql'] = f.get('codeql', 0) + (m['id'] in cf)
res = dict(
  rule=json.load(open(B + 'select2.json'))['rule'], date='2026-11-09',
  tools=dict(codeql=('2.x bundle, python-security-extended' if CQL else None), cryptorot=report.VERSION, bandit=subprocess.check_output(['bandit', '--version']).decode().split()[1], semgrep=subprocess.check_output(['semgrep', '--version']).decode().strip()),
  repos=repos,
  totals=dict(files=sum(r['files'] for r in repos), loc=sum(r['loc'] for r in repos), total=sum(r['total'] for r in repos), shipped=sum(r['shipped'] for r in repos), blind=sum(r['blind'] for r in repos),
              real=len(real), false=len(fal), unsure=len(uns), bandit_real=sum(l['bandit'] for l in real), semgrep_real=sum(l['semgrep'] for l in real),
              bandit_false=sum(l['bandit'] for l in fal), semgrep_false=sum(l['semgrep'] for l in fal), codeql_real=sum(l['codeql'] for l in real), codeql_false=sum(l['codeql'] for l in fal)),
  byclock={k: dict(n=sum(1 for l in real if l['clock'] == k), bandit=sum(l['bandit'] for l in real if l['clock'] == k), semgrep=sum(l['semgrep'] for l in real if l['clock'] == k), codeql=sum(l['codeql'] for l in real if l['clock'] == k)) for k in ('now', 'policy', 'quantum')},
  mutants=dict(n=len(pos), controls=len(neg), cryptorot_detected=s04['detected'], cryptorot_declared=s04['declared'], cryptorot_missed=s04['missed'], cryptorot_fp=s04['false_positives'],
               bandit=sum(m['id'] in bf for m in pos), bandit_fp=sum(m['id'] in bf for m in neg), semgrep=sum(m['id'] in sf for m in pos), semgrep_fp=sum(m['id'] in sf for m in neg), codeql=(sum(m['id'] in cf for m in pos) if cm is not None else None), codeql_fp=(sum(m['id'] in cf for m in neg) if cm is not None else None), families=fam),
  labels=labels, missed=missed)
json.dump(res, open('web/data/round2.json', 'w'), separators=(',', ':'))
print(json.dumps(res['totals']), json.dumps(res['byclock']), {k: v for k, v in res['mutants'].items() if k != 'families'})
