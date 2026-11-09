"""Bridge between the CryptoRot engine (./engine) and the dashboard.

The engine decides everything. This file runs report.analyze(), the same
function the terminal uses, keeps its output untouched as `rep`, and adds the
two display-only things the report does not carry: file line counts and the
surrounding statement for each finding.
"""
import os, sys, tempfile, tokenize, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'engine'))
import report as rpt        # noqa: E402
from model import PRIMS, CLOCK_LABEL, SOURCES  # noqa: E402

ENGINE = 'cryptorot ' + rpt.VERSION


def meta():
    """Per-primitive facts the dashboard shows. Straight from model.py."""
    out = {}
    for pid, p in PRIMS.items():
        out[pid] = dict(title=p['title'], clock=p['clock'], why=p['why'], family=p['family'],
                        sources=p['sources'])
    return dict(prims=out, clocks=CLOCK_LABEL,
                sources={k: dict(title=v[0], url=v[1]) for k, v in SOURCES.items()})


def _loc(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return len(f.read().splitlines())


def _ctx(lines, lineno, cap=8):
    """Whole logical statement starting at lineno (display only)."""
    try:
        it = iter(l + '\n' for l in lines[lineno - 1:])
        end = lineno
        for tok in tokenize.generate_tokens(lambda: next(it)):
            end = lineno + tok.end[0] - 1
            if tok.type == tokenize.NEWLINE:
                break
        out = [l.rstrip()[:120] for l in lines[lineno - 1:min(end, lineno - 1 + cap)]]
        if end - lineno + 1 > cap:
            out.append('...')
        return out if len(out) > 1 else None
    except Exception:
        return None


def scan_repo(root, name, version, date=None):
    t0 = time.perf_counter()
    rep = rpt.analyze(root)
    src, ctx = {}, {}
    for r in rep['findings']:
        if r['file'] not in src:
            with open(os.path.join(root, r['file']), 'r', encoding='utf-8', errors='replace') as fh:
                src[r['file']] = fh.read().splitlines()
        c = _ctx(src[r['file']], r['line'])
        if c:
            ctx['%s:%d' % (r['file'], r['line'])] = c
    files = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ('.git', '__pycache__')]
        for f in fn:
            if f.endswith('.py'):
                p = os.path.join(dp, f)
                files.append(dict(path=os.path.relpath(p, root).replace(os.sep, '/'), loc=_loc(p)))
    files.sort(key=lambda z: z['path'])
    repo = dict(name=name, version=version, files=files, rep=rep, ctx=ctx,
                scan_s=round(time.perf_counter() - t0, 3))
    if date:
        repo['date'] = date
    return repo


def scan_code(code):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'pasted.py'), 'w', encoding='utf-8') as f:
            f.write(code)
        return scan_repo(d, 'pasted code', 'snippet')
