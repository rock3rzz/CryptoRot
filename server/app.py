"""CryptoRot scan service. Proprietary. Copyright (c) 2026 Rohitkumar V Navalgund. All rights reserved.

Receives Python source, returns findings. The rules and the resolver stay on
this machine; clients only ever see the report.
"""
import os, sys, time, tempfile, hmac, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'engine'))
sys.path.insert(0, os.path.join(ROOT, 'web'))
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import adapter, selftest, report as rpt

ORIGINS = [o for o in os.environ.get('CR_ORIGINS', '').split(',') if o]
KEYS = [k for k in os.environ.get('CR_KEYS', '').split(',') if k]
LIMIT, WINDOW = int(os.environ.get('CR_RATE', '30')), 3600
MAX_FILES, MAX_BYTES = 400, 2_000_000

app = FastAPI(title='CryptoRot', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS or ['http://localhost:8000'],
                   allow_methods=['POST', 'GET'], allow_headers=['content-type', 'x-api-key'])
_hits = collections.defaultdict(list)


def guard(req: Request):
    if KEYS:
        k = req.headers.get('x-api-key', '')
        if not any(hmac.compare_digest(k, x) for x in KEYS):
            raise HTTPException(401, 'invalid key')
    ip = (req.headers.get('x-forwarded-for') or req.client.host or '?').split(',')[0].strip()
    now = time.time(); h = _hits[ip]
    h[:] = [t for t in h if now - t < WINDOW]
    if len(h) >= LIMIT:
        raise HTTPException(429, 'rate limit reached, try again later')
    h.append(now)


class ScanIn(BaseModel):
    name: str = 'pasted code'
    files: dict[str, str]


@app.get('/health')
def health():
    return {'ok': True}


@app.post('/scan')
def scan(body: ScanIn, req: Request):
    guard(req)
    if not body.files or len(body.files) > MAX_FILES or sum(len(v) for v in body.files.values()) > MAX_BYTES:
        raise HTTPException(413, 'too many files or too large')
    with tempfile.TemporaryDirectory() as d:
        for rel, text in body.files.items():
            p = os.path.normpath(os.path.join(d, rel))
            if not p.startswith(d + os.sep):
                raise HTTPException(400, 'bad path')
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(text)
        name = body.name[:80]
        return adapter.scan_repo(d, name, 'snippet' if name == 'pasted code' else 'local folder')


@app.post('/selftest')
def run_selftest(req: Request):
    guard(req)
    t0 = time.perf_counter()
    rows, s = selftest.evaluate(selftest.scan_v04)
    return {'rows': [{'id': r['id'], 'state': r['state']} for r in rows], 's': s,
            'ms': round((time.perf_counter() - t0) * 1000)}


class ExportIn(BaseModel):
    kind: str
    name: str = 'report'
    rep: dict


@app.post('/export')
def export(body: ExportIn, req: Request):
    guard(req)
    if body.kind == 'cbom':
        return rpt.to_cbom(body.rep, body.name[:80])
    if body.kind == 'sarif':
        return rpt.to_sarif(body.rep)
    raise HTTPException(400, 'unknown kind')
