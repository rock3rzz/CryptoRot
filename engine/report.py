"""
CryptoRot report layer, v0.4.

analyze() is the one function both the terminal CLI and the browser call, so
the two cannot disagree: the JSON they produce is the same bytes.
"""

import json
from collections import Counter

from ast_scanner import scan_directory
import model
from model import PRIMS, SOURCES, CLOCK_ORDER, CONF_ORDER, classify, rsa_strength, ec_strength

VERSION = "0.4.0"
SCOPE_ORDER = {"source": 0, "example": 1, "test": 2}


def _trail(steps):
    return [{"kind": k, "line": ln, "text": t} for k, ln, t in steps]


def _finding(f):
    p = PRIMS[f.primitive]
    purpose = set(f.purpose)
    c = classify(f.primitive, dict(purpose=purpose, benign=f.benign, context=f.context,
                                   key_bits=f.key_bits, curve_bits=f.curve_bits))
    param = {}
    if f.key_bits is not None:
        param["key_bits"] = f.key_bits
        param["classical_strength"] = rsa_strength(f.key_bits)
    if f.curve_bits is not None:
        param["curve"] = f.curve
        param["curve_bits"] = f.curve_bits
        param["classical_strength"] = ec_strength(f.curve_bits)
    trail = _trail(f.trail)
    if f.reach and f.reach != "test":
        trail.append({"kind": "reach", "line": None, "text": f.reach_note})
    trail.append({"kind": "verdict", "line": None, "text": c["status"]})
    srcs = list(p["sources"])
    if f.benign:
        srcs = []
    return {
        "file": f.file, "line": f.line, "primitive": f.primitive, "title": p["title"],
        "clock": c["clock"], "due": c["due"], "hard_stop": c["hard_stop"],
        "exposure": c["exposure"], "status": c["status"],
        "confidence": f.confidence, "scope": f.scope, "role": f.role,
        "reach": f.reach, "reach_note": f.reach_note, "occurrences": 1,
        "api": f.api, "snippet": f.snippet, "purpose": sorted(purpose),
        "param": param, "trail": trail, "sources": srcs, "cwe": p["cwe"],
        "why": p["why"], "fix": c["fix"],
    }


def _sort_key(r):
    return (CLOCK_ORDER[r["clock"]], r["due"] or 0, CONF_ORDER[r["confidence"]],
            SCOPE_ORDER[r["scope"]], r["file"], r["line"], r["primitive"])


def analyze(root):
    findings, blind, cov = scan_directory(root)
    rows = sorted((_finding(f) for f in findings), key=_sort_key)
    merged, seen = [], {}
    for x in rows:   # two identical calls on one line are one finding, counted twice
        k = (x["file"], x["line"], x["primitive"], x["api"], x["snippet"])
        if k in seen:
            seen[k]["occurrences"] += 1
            continue
        seen[k] = x
        merged.append(x)
    for x in merged:
        if x["occurrences"] > 1:
            x["trail"].insert(len(x["trail"]) - 1, {"kind": "note", "line": x["line"],
                "text": f"the same call appears {x['occurrences']} times on this line"})
    rows = merged
    summary = {
        "total": len(rows),
        "by_clock": dict(Counter(r["clock"] for r in rows)),
        "by_clock_source": dict(Counter(r["clock"] for r in rows if r["scope"] == "source")),
        "by_scope": dict(Counter(r["scope"] for r in rows)),
        "by_confidence": dict(Counter(r["confidence"] for r in rows)),
        "by_primitive": dict(Counter(r["primitive"] for r in rows)),
    }
    used = sorted({s for r in rows for s in r["sources"]})
    return {
        "tool": "cryptorot", "version": VERSION,
        "coverage": {"files_total": cov.files_total, "files_parsed": cov.files_parsed,
                     "files_failed": cov.files_failed, "loc": cov.loc,
                     "other_language_files": cov.other_language_files},
        "summary": summary,
        "blind_spots": [{"file": b.file, "line": b.line, "kind": b.kind, "detail": b.detail}
                        for b in sorted(blind, key=lambda b: (b.file, b.line, b.kind))],
        "findings": rows,
        "sources": {s: {"title": SOURCES[s][0], "url": SOURCES[s][1]} for s in used},
    }


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)


# ------------------------------------------------------------- CycloneDX

def _asset_name(r):
    p = r["primitive"]
    pm = r["param"]
    if p == "rsa" or (p == "weak_key" and "key_bits" in pm):
        return f"RSA-{pm['key_bits']}" if "key_bits" in pm else "RSA"
    if p == "weak_key":
        return f"EC-{pm.get('curve', 'unknown')}"
    if p == "ecdsa":
        return f"ECDSA-{pm['curve']}" if "curve" in pm else "ECDSA"
    return {"md5": "MD5", "sha1": "SHA-1", "ecdh": "ECDH", "dh": "DH",
            "ecb_mode": "ECB", "hardcoded_key": "hardcoded-secret"}[p]


def to_cbom(report, name="scanned-project"):
    """CycloneDX 1.6 cryptographic bill of materials with evidence."""
    groups = {}
    for r in report["findings"]:
        if r["clock"] == "benign":
            pass
        groups.setdefault((r["primitive"] if r["primitive"] != "weak_key" else "weak_key", _asset_name(r)), []).append(r)
    comps = []
    for (prim, nm), rs in sorted(groups.items()):
        meta = PRIMS[prim]["cbom"]
        first = rs[0]
        ref = f"crypto/{prim}/{nm}".lower().replace(" ", "-")
        if prim == "hardcoded_key":
            cp = {"assetType": "related-crypto-material",
                  "relatedCryptoMaterialProperties": {"type": "secret-key"}}
        else:
            ap = {"primitive": meta["primitive"]}
            if prim == "ecb_mode":
                ap["mode"] = "ecb"
            if "key_bits" in first["param"]:
                ap["parameterSetIdentifier"] = str(first["param"]["key_bits"])
            if "curve" in first["param"]:
                ap["curve"] = first["param"]["curve"]
            strength = first["param"].get("classical_strength")
            if strength:
                ap["classicalSecurityLevel"] = strength
            if meta.get("quantum") is not None or prim in ("md5", "sha1"):
                ap["nistQuantumSecurityLevel"] = 0
            cp = {"assetType": "algorithm", "algorithmProperties": ap}
        comps.append({
            "type": "cryptographic-asset", "bom-ref": ref, "name": nm,
            "cryptoProperties": cp,
            "evidence": {"occurrences": [{"location": r["file"], "line": r["line"]} for r in rs]},
            "properties": [
                {"name": "cryptorot:clock", "value": first["clock"]},
                {"name": "cryptorot:due", "value": str(first["due"]) if first["due"] else "now"},
                {"name": "cryptorot:confidence", "value": first["confidence"]},
                {"name": "cryptorot:occurrences", "value": str(len(rs))},
            ],
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "cryptorot", "version": VERSION}]},
                     "component": {"type": "application", "name": name}},
        "components": comps,
    }


# ----------------------------------------------------------------- SARIF

_LEVEL = {"now": "error", "policy": "warning", "quantum": "warning", "benign": "note"}


def to_sarif(report):
    prims = sorted({r["primitive"] for r in report["findings"]})
    rules = [{"id": f"CR-{p}", "name": PRIMS[p]["title"],
              "shortDescription": {"text": PRIMS[p]["title"]},
              "fullDescription": {"text": PRIMS[p]["why"]},
              "helpUri": SOURCES[PRIMS[p]["sources"][0]][1] or "https://csrc.nist.gov/pubs/ir/8547/final"}
             for p in prims]
    results = []
    for r in report["findings"]:
        results.append({
            "ruleId": f"CR-{r['primitive']}", "level": _LEVEL[r["clock"]],
            "message": {"text": f"{r['title']}: {r['status']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["file"]},
                                                "region": {"startLine": max(r["line"], 1)}}}],
            "properties": {"clock": r["clock"], "due": r["due"], "confidence": r["confidence"],
                           "scope": r["scope"], "role": r["role"],
                           "trail": [t["text"] for t in r["trail"]]},
        })
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "cryptorot", "version": VERSION, "rules": rules}},
                      "results": results}]}
