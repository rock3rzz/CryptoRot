"""Builds web/data/findings.json: scans the pinned benchmark projects, the python-rsa release history and the self-test.
Run bench/fetch.sh first. Run from the repository root: python3 bench/make_data.py"""
import json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'web')); sys.path.insert(0, os.path.join(ROOT, 'engine'))
os.chdir(ROOT)
import adapter
import selftest
B = 'bench/repos/'
def g(r, *a): return subprocess.check_output(['git', '-C', r, *a]).decode().strip()
repos = []
for n in ('python-rsa', 'python-ecdsa', 'python-jose'):
    r = B + n
    repos.append(adapter.scan_repo(r, n, g(r, 'log', '-1', '--format=%h'), g(r, 'log', '-1', '--format=%ad', '--date=format:%Y-%m')))
B2 = 'bench/repos/'
for n in ('pyjwt', 'authlib', 'paramiko', 'pycryptodome', 'pyopenssl', 'pyotp', 'itsdangerous', 'certbot', 'django'):
    r = B2 + n
    repos.append(adapter.scan_repo(r, n, g(r, 'log', '-1', '--format=%h'), g(r, 'log', '-1', '--format=%ad', '--date=format:%Y-%m')))
H = 'bench/repos/python-rsa-history'; hist = []
for t in ['version-3.0', 'version-3.1.4', 'version-3.4.2', 'version-4.0', 'version-4.4', 'version-4.7.2', 'version-4.9']:
    subprocess.run(['git', '-C', H, 'checkout', '-q', '-f', t], check=True)
    h = adapter.scan_repo(H, 'python-rsa', t.replace('version-', ''), g(H, 'log', '-1', '--format=%ad', '--date=format:%Y-%m', t))
    h.pop('ctx'); hist.append(h)
    print(t, len(h['rep']['findings']))
cur = dict(repos[0]); hist.append(cur)
repos[0]['versions'] = hist
# self-test: v0.4 live result next to the stored v0.3 result on the same mutants
rows, s04 = selftest.evaluate(selftest.scan_v04)
v03 = json.load(open('bench/selftest_v03.json'))
st03 = {r['id']: r['state'] for r in v03['rows']}
st = dict(summary04=s04, summary03=v03['summary'],
          rows=[dict(id=r['id'], family=r['family'], operator=r['operator'], mode=r['mode'], note=r['note'],
                     code=r['code'], v04=r['state'], v03=st03.get(r['id'])) for r in rows])
json.dump(dict(engine=adapter.ENGINE, repos=repos, selftest=st), open('web/data/findings.json', 'w'), separators=(',', ':'))
print([(r['name'], len(r['rep']['findings'])) for r in repos], s04)
