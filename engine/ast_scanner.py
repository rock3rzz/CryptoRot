"""
CryptoRot AST scanner, v0.4 (Python source).

v0.3 matched the dotted name of a call as written. That is exactly what
mutation studies of crypto-misuse detectors say fails: the same misuse
written a slightly different way (aliased import, a name held in a
variable, a value passed through a helper function) slips past. v0.4 adds
a small resolver so those spellings land on the same finding, and where it
cannot resolve something it says so instead of staying silent.

What the resolver does, all on the standard library `ast`:
  * import aliases        import hashlib as h / from hashlib import md5 as m
  * constant folding      "md" + "5", f"md{5}", NAME = "md5", "MD5".lower()
  * keyword arguments     hashlib.new(name="md5"), usedforsecurity=False
  * getattr indirection   getattr(hashlib, "md5")
  * one-hop propagation   def digest(algo): hashlib.new(algo)  +  digest("md5")
  * key sinks             a literal reaching AES.new / hmac.new / jwt.encode
  * parameters            RSA key size, EC curve

Every finding carries a trail (the evidence chain) and a confidence tier.
Everything the resolver could not resolve is returned as a blind spot.
"""

import ast
import os
import re
import warnings
from dataclasses import dataclass, field

from rules import (
    CALL_PATTERNS, HASHLIB_NEW_ALGOS, ECB_ATTR_SUFFIXES, ECB_CALL_PATTERNS,
    SECRET_NAME_HINTS, SECRET_MIN_LEN, KEY_SINKS, KEY_SINK_MIN_LEN,
    RSA_SIZE_ARG, EC_CURVE_ARG, ENC_WORDS, KEX_WORDS, SIG_WORDS, PWD_WORDS,
    INTEGRITY_WORDS, TEST_FILE_PREFIXES, TEST_DIRS,
)

UNRES = object()
MAX_DEPTH = 8
OTHER_LANG_EXT = {".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".cc", ".cpp",
                  ".h", ".hpp", ".rs", ".rb", ".php", ".cs", ".kt", ".swift"}
CRYPTO_STAR_MODULES = ("hashlib", "Crypto", "Cryptodome", "cryptography", "rsa",
                       "ecdsa", "jose", "jwt", "hmac")


@dataclass
class Finding:
    file: str
    line: int
    primitive: str
    snippet: str = ""
    confidence: str = "proven"       # proven | probable | heuristic
    scope: str = "source"            # source | test | example
    role: str = "consumer"           # consumer | provider
    api: str = ""                    # canonical API that matched
    benign: bool = False
    key_bits: int = None
    curve: str = None
    curve_bits: int = None
    purpose: tuple = ()
    context: str = ""                # e.g. collision-insensitive use of SHA-1
    reach: str = ""                  # import-time | public-api | reached | unreferenced | test
    reach_note: str = ""
    trail: list = field(default_factory=list)


@dataclass
class BlindSpot:
    file: str
    line: int
    kind: str
    detail: str


@dataclass
class Coverage:
    files_total: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    loc: int = 0
    other_language_files: int = 0


# ---------------------------------------------------------------- helpers

def _dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _call_target_name(call_node):
    func = call_node.func
    if isinstance(func, ast.Attribute):
        return _dotted_name(func)
    if isinstance(func, ast.Name):
        return func.id
    return None


def _match_suffix(dotted, suffixes):
    if not dotted:
        return False
    return dotted.split(".")[-1] in suffixes


def _tokens(ident):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", ident)
    return [t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t]


def file_scope(rel_path):
    parts = rel_path.replace("\\", "/").lower().split("/")
    fname = parts[-1]
    dirs = parts[:-1]
    if any(d in ("examples", "example", "docs", "doc") for d in dirs):
        return "example"
    if any(d in TEST_DIRS or _TESTISH.search(d) for d in dirs) or fname.startswith(TEST_FILE_PREFIXES) \
            or fname.endswith("_test.py") or fname.endswith("_tests.py") \
            or fname in ("test.py", "tests.py", "selftest.py"):
        return "test"
    if any(w in fname for w in ("speedtest", "benchmark", "timing_table")):
        return "example"
    return "source"


_TESTISH = re.compile(r"(^|[-_])(test|tests|ci|selftest|testing)([-_]|$)")


def _secret_name(name):
    """The last word of the variable name must say it holds a secret. `session_key`
    qualifies, `key_salt`, `token_endpoint_auth_method` and `API_KEY_URL_V4` do not."""
    toks = [t for t in name.lower().split("_") if t]
    while len(toks) > 1 and re.sub(r"\d+$", "", toks[-1]) in ("str", "string", "pem", "bytes", "data", "text", "b64", "hex", "value", "val", "b"):
        toks.pop()
    last = re.sub(r"\d+$", "", toks[-1]) if toks else ""
    return last in ("key", "secret", "password", "passwd", "pwd", "token", "apikey", "passphrase", "secretkey") \
        or name.lower().endswith(("api_key", "secret_key"))


def _entropy(v):
    from collections import Counter
    from math import log2
    c = Counter(v)
    return -sum(n / len(v) * log2(n / len(v)) for n in c.values())


def _secret_value(v):
    """Does the literal look like a secret rather than a label, a URL or a dotted name?"""
    if "-----BEGIN" in v and "PRIVATE KEY" in v and "-----END" in v:
        return True
    if re.search(r"\s", v) or "://" in v or "/" in v:
        return False
    if re.fullmatch(r"[A-Za-z_][\w]*(\.[\w]+)+", v):          # dotted module or setting path
        return False
    words = [w for w in re.split(r"[_\-]", v) if w]
    if len(words) >= 2 and all(w.isalpha() and (w == w.lower() or w == w.upper()) for w in words):
        return False                                             # snake or kebab words
    if re.fullmatch(r"[0-9a-fA-F]{16,}", v) or re.fullmatch(r"[A-Za-z0-9+/=_\-]{16,}", v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        return _entropy(v) >= 3.0
    return _entropy(v) >= 3.6 and len(v) >= 16


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
        if k.arg is None:                       # **{"usedforsecurity": False}, possibly inside cast(T, {...})
            d = k.value
            while isinstance(d, ast.Call) and d.args:
                d = d.args[-1]
            if isinstance(d, ast.Dict):
                for kk, vv in zip(d.keys, d.values):
                    if isinstance(kk, ast.Constant) and kk.value == name:
                        return vv
    return None


def _arg(call, idx, kwname):
    """The argument node at position idx or keyword kwname, else None."""
    if idx is not None and len(call.args) > idx and not isinstance(call.args[idx], ast.Starred):
        return call.args[idx]
    if kwname:
        return _kw(call, kwname)
    return None


def _src(node, lines, limit=60):
    try:
        text = ast.get_source_segment("\n".join(lines), node) or ""
    except Exception:
        text = ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------- per-file scan

class _FileScan:
    def __init__(self, rel, source, tree, repo_defs):
        self.rel = rel
        self.lines = source.splitlines()
        self.tree = tree
        self.repo_classes, self.repo_funcs = repo_defs
        self.findings = []
        self.blind = []
        self.imports = {}            # local -> (canonical, line)
        self.parents = {}
        self.func_defs = {}          # name -> [FunctionDef]
        self.call_sites = {}         # callee name -> [Call]
        self.scope_cache = {}
        self.vocab = {}              # purpose tag -> {identifier tokens}
        self.sink_hits = []          # (assign line, sink api, call line)
        self.scope = file_scope(rel)
        self._prepass()

    # ---- pre-pass -------------------------------------------------------
    def _prepass(self):
        for node in ast.walk(self.tree):
            for ch in ast.iter_child_nodes(node):
                self.parents[ch] = node
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.imports[a.asname] = (a.name, node.lineno)
                    else:
                        root = a.name.split(".")[0]
                        self.imports.setdefault(root, (root, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    if a.name == "*":
                        if mod.split(".")[0] in CRYPTO_STAR_MODULES:
                            self.blind.append(BlindSpot(self.rel, node.lineno, "star-import",
                                f"`from {mod} import *` hides which crypto names are in use"))
                        continue
                    local = a.asname or a.name
                    canon = (mod + "." + a.name) if mod else a.name
                    self.imports[local] = (canon, node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.func_defs.setdefault(node.name, []).append(node)
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name):
                    self.call_sites.setdefault(f.id, []).append(node)
                elif isinstance(f, ast.Attribute):
                    self.call_sites.setdefault(f.attr, []).append(node)
            ident = None
            if isinstance(node, ast.Name):
                ident = node.id
            elif isinstance(node, ast.Attribute):
                ident = node.attr
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                ident = node.name
            elif isinstance(node, ast.arg):
                ident = node.arg
            if ident:
                for tok in _tokens(ident):
                    self._tag(tok, ident)
        self.sig_forced = False

    def _tag(self, tok, ident):
        def hit(tag, cond):
            if cond:
                self.vocab.setdefault(tag, set()).add(ident)
        hit("enc", tok.startswith(("encrypt", "decrypt", "oaep", "encaps", "decaps")))
        hit("kex", tok.startswith(("ecdh", "exchang", "diffie", "agreem")))
        hit("sig", tok in ("sign", "signs", "signed", "signing", "signer", "sig", "sigs")
            or tok.startswith(("signat", "verif")))
        hit("pwd", tok in ("password", "passwd", "pwd") or tok.startswith(("pbkdf", "bcrypt")))
        hit("integrity", tok in ("checksum", "fingerprint", "etag", "cache", "hexdigest"))

    # ---- scopes and constant folding -------------------------------------
    def _enclosing_func(self, node):
        n = self.parents.get(node)
        while n is not None:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return n
            n = self.parents.get(n)
        return None

    def _scope_consts(self, scope):
        """name -> (value node, line) for names bound exactly once in scope."""
        key = id(scope)
        if key in self.scope_cache:
            return self.scope_cache[key]
        counts, single = {}, {}

        def bind(name, node, line):
            counts[name] = counts.get(name, 0) + 1
            single[name] = (node, line)

        def walk(nodes):
            for st in nodes:
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        if isinstance(t, ast.Name):
                            bind(t.id, st.value, st.lineno)
                        else:
                            for n in ast.walk(t):
                                if isinstance(n, ast.Name):
                                    bind(n.id, None, st.lineno)
                elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                    bind(st.target.id, st.value, st.lineno)
                elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                    bind(st.target.id, None, st.lineno)
                elif isinstance(st, (ast.For, ast.AsyncFor)):
                    for n in ast.walk(st.target):
                        if isinstance(n, ast.Name):
                            bind(n.id, None, st.lineno)
                elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bind(st.name, None, st.lineno)
                    continue
                for field_name in ("body", "orelse", "finalbody", "handlers"):
                    sub = getattr(st, field_name, None)
                    if isinstance(sub, list):
                        walk([x for x in sub if isinstance(x, ast.stmt)] +
                             [h for x in sub if isinstance(x, ast.ExceptHandler) for h in x.body])

        body = scope.body if hasattr(scope, "body") and isinstance(scope.body, list) else []
        walk(body)
        out = {n: v for n, v in single.items() if counts[n] == 1 and v[0] is not None}
        self.scope_cache[key] = out
        return out

    def _lookup_const(self, name, at_node):
        fn = self._enclosing_func(at_node)
        if fn is not None:
            c = self._scope_consts(fn)
            if name in c:
                return c[name]
            if name in self._params(fn):
                return "param"
        c = self._scope_consts(self.tree)
        return c.get(name)

    @staticmethod
    def _params(fn):
        if isinstance(fn, ast.Lambda):
            a = fn.args
        else:
            a = fn.args
        names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
        if a.vararg: names.append(a.vararg.arg)
        if a.kwarg: names.append(a.kwarg.arg)
        return names

    def fold(self, node, steps, depth=0):
        """Fold node to a str/bytes/int constant, appending evidence to
        steps. Returns UNRES when the value is not statically known."""
        if depth > MAX_DEPTH or node is None:
            return UNRES
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes, int)) and not isinstance(node.value, bool):
                return node.value
            if isinstance(node.value, bool):
                return node.value
            return UNRES
        if isinstance(node, ast.Name):
            hit = self._lookup_const(node.id, node)
            if hit is None or hit == "param":
                return UNRES
            val = self.fold(hit[0], steps, depth + 1)
            if val is not UNRES:
                steps.append(("const", hit[1], f"`{node.id}` is assigned once, on line {hit[1]}, to {_show(val)}"))
            return val
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a = self.fold(node.left, steps, depth + 1)
            b = self.fold(node.right, steps, depth + 1)
            if a is not UNRES and b is not UNRES and type(a) == type(b) and not isinstance(a, bool):
                return a + b
            return UNRES
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            a = self.fold(node.left, steps, depth + 1)
            b = self.fold(node.right, steps, depth + 1)
            if isinstance(a, (str, bytes)) and isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 4096:
                return a * b
            if isinstance(a, int) and isinstance(b, int) and not isinstance(a, bool):
                return a * b
            return UNRES
        if isinstance(node, ast.JoinedStr):
            out = ""
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    out += v.value
                elif isinstance(v, ast.FormattedValue) and v.format_spec is None and v.conversion == -1:
                    inner = self.fold(v.value, steps, depth + 1)
                    if inner is UNRES or isinstance(inner, bytes):
                        return UNRES
                    out += str(inner)
                else:
                    return UNRES
            return out
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = self.fold(node.func.value, steps, depth + 1)
            meth = node.func.attr
            if isinstance(base, str) and not node.keywords and meth in ("lower", "upper", "strip") and not node.args:
                return getattr(base, meth)()
            if isinstance(base, str) and meth == "encode" and len(node.args) <= 1 and not node.keywords:
                return base.encode("utf-8") if not node.args else UNRES
            if isinstance(base, bytes) and meth == "decode" and not node.args and not node.keywords:
                try:
                    return base.decode("utf-8")
                except Exception:
                    return UNRES
            if meth == "join" and isinstance(base, str) and len(node.args) == 1 \
                    and isinstance(node.args[0], (ast.List, ast.Tuple)):
                parts = [self.fold(e, steps, depth + 1) for e in node.args[0].elts]
                if all(isinstance(p, str) for p in parts):
                    return base.join(parts)
            return UNRES
        if isinstance(node, ast.Subscript):
            c = node.value
            if isinstance(c, ast.Name):
                hit = self._lookup_const(c.id, c)
                c = hit[0] if (hit not in (None, "param")) else None
            if not isinstance(c, (ast.List, ast.Tuple, ast.Dict)):
                return UNRES
            idx = self.fold(node.slice, steps, depth + 1)
            if idx is UNRES:
                return UNRES
            if isinstance(c, ast.Dict):
                for k, v in zip(c.keys, c.values):
                    if k is not None and self.fold(k, [], depth + 1) == idx:
                        return self.fold(v, steps, depth + 1)
                return UNRES
            if isinstance(idx, int) and -len(c.elts) <= idx < len(c.elts):
                return self.fold(c.elts[idx], steps, depth + 1)
        return UNRES

    # ---- one-hop propagation through a local function --------------------
    def param_values(self, name_node):
        """If name_node is a parameter of its enclosing function, fold the
        matching argument at every call site in this file.
        Returns (values, complete, steps) or None when not a parameter."""
        fn = self._enclosing_func(name_node)
        if fn is None or isinstance(fn, ast.Lambda) or name_node.id not in self._params(fn):
            return None
        a = fn.args
        pos = [x.arg for x in a.posonlyargs + a.args]
        is_method = bool(pos) and pos[0] in ("self", "cls")
        idx = pos.index(name_node.id) if name_node.id in pos else None
        defaults = {}
        for p, d in zip(reversed(pos), reversed(a.defaults)):
            defaults[p] = d
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if d is not None:
                defaults[p.arg] = d
        values, steps, complete = [], [], True
        sites = [c for c in self.call_sites.get(fn.name, []) if c is not None]
        if not sites:
            complete = False
        for call in sites:
            node = None
            if idx is not None:
                eff = idx - 1 if (is_method and isinstance(call.func, ast.Attribute)) else idx
                if eff >= 0 and len(call.args) > eff and not isinstance(call.args[eff], ast.Starred):
                    node = call.args[eff]
            if node is None:
                node = _kw(call, name_node.id)
            if node is None and name_node.id in defaults:
                node = defaults[name_node.id]
            sub = []
            v = self.fold(node, sub) if node is not None else UNRES
            if v is UNRES:
                complete = False
            else:
                values.append((v, call.lineno))
                steps.append(("param", call.lineno,
                              f"`{fn.name}(...)` is called on line {call.lineno} with {_show(v)} for `{name_node.id}`"))
        if not sites and name_node.id in defaults:
            sub = []
            v = self.fold(defaults[name_node.id], sub)
            if v is not UNRES:
                values.append((v, fn.lineno))
                steps.append(("param", fn.lineno, f"`{name_node.id}` defaults to {_show(v)}"))
        return values, complete, steps

    # ---- names -----------------------------------------------------------
    def canon(self, lit):
        if not lit:
            return lit, None
        root, _, rest = lit.partition(".")
        imp = self.imports.get(root)
        if imp is None:
            return lit, None
        c = imp[0] + (("." + rest) if rest else "")
        return c, imp

    @staticmethod
    def _keys(lit, canon):
        keys = [lit]
        if canon and canon != lit:
            keys.append(canon)
            seg = canon.split(".")
            for i in range(1, len(seg) - 1):
                keys.append(".".join(seg[i:]))
        return keys

    def match_api(self, table, lit, canon):
        for k in self._keys(lit, canon):
            if k in table:
                return k, table[k]
        return None, None

    # ---- emission --------------------------------------------------------
    def snippet(self, lineno):
        return self.lines[lineno - 1].strip() if 1 <= len(self.lines) and 1 <= lineno <= len(self.lines) else ""

    def emit(self, node_or_line, prim, confidence, api, trail, **kw):
        if prim == "ecdh" and not kw.get("benign"):
            if not hasattr(self, "_pq"):
                self._pq = bool(re.search(r"ml_?kem|kyber", "\n".join(self.lines), re.I))
            if self._pq:
                trail = list(trail) + [("note", None, "this file also uses ML-KEM, so the elliptic-curve half is part of a hybrid key exchange")]
                kw["benign"] = True
                kw["context"] = "hybrid-pq"
        line = node_or_line if isinstance(node_or_line, int) else node_or_line.lineno
        f = Finding(file=self.rel, line=line, primitive=prim, snippet=self.snippet(line),
                    confidence=confidence, scope=self.scope, api=api, trail=list(trail), **kw)
        self.findings.append(f)
        return f

    def purpose_for(self, prim, lit, canon):
        tags = set()
        for t in ("enc", "kex", "sig", "pwd", "integrity"):
            if self.vocab.get(t):
                tags.add(t)
        if prim == "ecdsa" and (canon or lit or "").split(".")[0] == "ecdsa":
            tags.add("sig")
        if prim == "ecdsa" and "SigningKey" in (canon or lit or ""):
            tags.add("sig")
        return tags

    def purpose_trail(self, tags):
        out = []
        for t in ("sig", "enc", "kex", "pwd", "integrity"):
            if t in tags and self.vocab.get(t):
                words = sorted(self.vocab[t])[:4]
                label = {"sig": "signing", "enc": "encryption", "kex": "key exchange",
                         "pwd": "password handling", "integrity": "checksums or caching"}[t]
                out.append(("purpose", None, f"this file's identifiers suggest {label} ({', '.join(words)})"))
        return out

    # ---- visitor ---------------------------------------------------------
    def run(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self.on_call(node)
            elif isinstance(node, ast.Attribute):
                self.on_attr(node)
            elif isinstance(node, ast.Assign):
                self.on_assign(node)
            elif isinstance(node, ast.AnnAssign):
                self.on_annassign(node)
        self.link_sinks()
        self.findings.sort(key=lambda f: (f.line, f.primitive))
        return self.findings, self.blind

    def role_for(self, api):
        """Provider if this codebase itself defines the API being called."""
        if not api:
            return "consumer"
        parts = api.split(".")
        if len(parts) >= 2 and parts[-2][:1].isupper():
            return "provider" if parts[-2] in self.repo_classes else "consumer"
        return "provider" if parts[-1] in self.repo_funcs and len(parts) >= 2 and parts[-1] not in ("new", "generate") else "consumer"

    def on_call(self, node):
        lit = _call_target_name(node)
        canon, imp = self.canon(lit)
        steps_base = []

        def resolve_step():
            if imp and canon != lit:
                return [("import", imp[1], f"`{lit}` resolves to `{canon}` through the import on line {imp[1]}")]
            return []

        # runtime code
        if lit in ("eval", "exec") and node.args and not isinstance(node.args[0], ast.Constant):
            self.blind.append(BlindSpot(self.rel, node.lineno, "runtime-code",
                                        f"`{lit}(...)` runs code built at runtime; anything inside is invisible to a static scan"))

        # ---- direct primitive calls
        key, prim = self.match_api(CALL_PATTERNS, lit, canon)
        if prim:
            literal_hit = key == lit
            rooted = (lit or "").split(".")[0] in self.imports
            conf = "proven" if (rooted or not literal_hit) else "probable"
            api = canon if canon else lit
            trail = [("call", node.lineno, f"`{_src(node, self.lines)}` calls `{api}`")]
            trail = resolve_step() + trail
            if conf == "probable":
                trail.append(("note", None, f"`{(lit or '').split('.')[0]}` is not imported in this file, so the match is by name only"))
            benign = False
            if prim in ("md5", "sha1"):
                ufs = _kw(node, "usedforsecurity")
                if ufs is not None:
                    st = []
                    v = self.fold(ufs, st)
                    if v is False:
                        benign = True
                        trail.append(("flag", node.lineno, "`usedforsecurity=False` is passed, so the code declares this is not a security check"))
            tags = self.purpose_for(prim, lit, canon)
            ctx = ""
            if prim in ("sha1", "md5"):
                anc = self.parents.get(node)
                while anc is not None:
                    if isinstance(anc, ast.Call):
                        nm = _dotted_name(anc.func) or ""
                        if any(t in nm for t in ("OAEP", "MGF1", "HMAC", "hmac", "HKDF", "pbkdf2")):
                            ctx = "collision-insensitive"
                            trail.append(("context", anc.lineno,
                                          f"it is an argument of `{nm}`, a construction that does not rely on collision resistance"))
                            break
                    anc = self.parents.get(anc)
            if not ctx:
                trail += self.purpose_trail(tags & ({"pwd", "integrity"} if prim in ("md5", "sha1") else {"sig", "enc", "kex"}))
            f = self.emit(node, prim, conf, api, trail, benign=benign, purpose=tuple(sorted(tags)),
                          role=self.role_for(key if key != lit else (canon or lit)), context=ctx)
            self.params(node, f, lit, canon, key)
            return

        # ---- ECB via modes.ECB()
        k2, _ = self.match_api({m: 1 for m in ECB_CALL_PATTERNS}, lit, canon)
        if k2:
            trail = resolve_step() + [("call", node.lineno, f"`{_src(node, self.lines)}` selects ECB mode")]
            self.emit(node, "ecb_mode", "proven" if (lit or "").split(".")[0] in self.imports else "probable",
                      canon or lit, trail)
            return

        # ---- hashlib.new(<name>)
        is_new = (canon == "hashlib.new") or (lit and lit.split(".")[-1] == "new"
                                              and lit.rsplit(".", 1)[0].endswith("hashlib"))
        if is_new:
            self.on_hashlib_new(node, lit, canon, resolve_step())
            return

        # ---- getattr(hashlib, "md5")
        if lit == "getattr" and len(node.args) >= 2:
            base = _dotted_name(node.args[0])
            bcanon, bimp = self.canon(base) if base else (None, None)
            if bcanon == "hashlib":
                st = []
                v = self.fold(node.args[1], st)
                if isinstance(v, str) and v.lower() in HASHLIB_NEW_ALGOS:
                    trail = [("call", node.lineno, f"`{_src(node, self.lines)}` looks the algorithm up by name"),
                             ] + [(a, b, c) for a, b, c in st] + \
                            [("resolve", node.lineno, f"the name folds to {_show(v)}, which is `hashlib.{HASHLIB_NEW_ALGOS[v.lower()]}`")]
                    self.emit(node, HASHLIB_NEW_ALGOS[v.lower()], "proven", "hashlib." + v.lower(), trail,
                              role="consumer")
                elif v is UNRES:
                    self.blind.append(BlindSpot(self.rel, node.lineno, "dynamic-algorithm",
                        f"`{_src(node, self.lines)}` picks a hash by a name that is not known statically"))
                return

        # ---- key sinks
        skey, sink = self.match_api(KEY_SINKS, lit, canon)
        if sink:
            self.on_key_sink(node, lit, canon, skey, sink, resolve_step())

    def on_hashlib_new(self, node, lit, canon, rstep):
        arg = _arg(node, 0, "name")
        if arg is None:
            return
        st = []
        v = self.fold(arg, st)
        base_trail = rstep + [("call", node.lineno, f"`{_src(node, self.lines)}` builds a hash by name")]
        if v is not UNRES and isinstance(v, str):
            algo = v.lower()
            if algo in HASHLIB_NEW_ALGOS:
                trail = base_trail + [(a, b, c) for a, b, c in st]
                if not isinstance(arg, ast.Constant):
                    trail.append(("resolve", node.lineno, f"the name folds to {_show(v)}"))
                prim = HASHLIB_NEW_ALGOS[algo]
                benign = False
                ufs = _kw(node, "usedforsecurity")
                if ufs is not None and self.fold(ufs, []) is False:
                    benign = True
                    trail.append(("flag", node.lineno, "`usedforsecurity=False` is passed, so the code declares this is not a security check"))
                tags = self.purpose_for(prim, lit, canon)
                self.emit(node, prim, "proven", "hashlib.new", trail, benign=benign,
                          purpose=tuple(sorted(tags)))
            return
        if isinstance(arg, ast.Name):
            pv = self.param_values(arg)
            if pv is not None:
                values, complete, psteps = pv
                hit = False
                for val, ln in values:
                    if isinstance(val, str) and val.lower() in HASHLIB_NEW_ALGOS:
                        hit = True
                        prim = HASHLIB_NEW_ALGOS[val.lower()]
                        trail = base_trail + [("param", ln, f"`{arg.id}` is a parameter of `{self._enclosing_func(arg).name}`")] + \
                                [s for s in psteps if s[1] == ln][:1]
                        self.emit(node, prim, "proven", "hashlib.new", trail,
                                  purpose=tuple(sorted(self.purpose_for(prim, lit, canon))))
                if not complete:
                    self.blind.append(BlindSpot(self.rel, node.lineno, "dynamic-algorithm",
                        f"`{_src(node, self.lines)}`: not every caller of `{self._enclosing_func(arg).name}` passes a known algorithm name"))
                return
        self.blind.append(BlindSpot(self.rel, node.lineno, "dynamic-algorithm",
                                    f"`{_src(node, self.lines)}` builds a hash from a name that is not known statically"))

    def on_key_sink(self, node, lit, canon, skey, sink, rstep):
        idx, kwname = sink
        arg = _arg(node, idx, kwname)
        if arg is None:
            return
        st = []
        v = self.fold(arg, st)
        if v is UNRES or isinstance(v, bool) or not isinstance(v, (str, bytes)) or len(v) < KEY_SINK_MIN_LEN:
            return
        if isinstance(v, str) and "-----BEGIN" in v and "PRIVATE" not in v:
            return          # a public key or certificate is not a secret
        api = canon or lit
        trail = rstep + [("call", node.lineno, f"`{_src(node, self.lines)}` passes a key to `{api}`")]
        trail += [(a, b, c) for a, b, c in st]
        if isinstance(arg, ast.Constant):
            trail.append(("literal", node.lineno, f"the key is a {len(v)}-character literal written in the source"))
        assign_line = None
        for a, b, c in st:
            if a == "const":
                assign_line = b
        if assign_line is not None and isinstance(arg, ast.Name):
            self.sink_hits.append((assign_line, api, node.lineno, trail))
            return
        self.emit(node, "hardcoded_key", "proven", api, trail)

    def params(self, node, f, lit, canon, key):
        """Key size and curve extraction for key-generation calls."""
        if f.primitive == "rsa":
            skey, spec = self.match_api(RSA_SIZE_ARG, lit, canon)
            if not spec:
                return
            arg = _arg(node, spec[0], spec[1])
            if arg is None:
                return
            st = []
            v = self.fold(arg, st)
            if v is UNRES and isinstance(arg, ast.Name):
                pv = self.param_values(arg)
                if pv and pv[0]:
                    vals = [x for x, _ in pv[0] if isinstance(x, int) and not isinstance(x, bool)]
                    if vals and pv[1]:
                        v = min(vals)
                        st = [s for s in pv[2]][:1]
            if isinstance(v, int) and not isinstance(v, bool):
                f.key_bits = v
                f.trail.append(("param", node.lineno, f"key size resolves to {v} bits"))
                f.trail += [(a, b, c) for a, b, c in st]
                if v < 2048:
                    self.emit(node, "weak_key", "proven", f.api,
                              [("call", node.lineno, f"`{_src(node, self.lines)}` generates an RSA key"),
                               ("param", node.lineno, f"the key size is {v} bits, below the 2048-bit minimum")] +
                              [(a, b, c) for a, b, c in st], key_bits=v)
            else:
                self.blind.append(BlindSpot(self.rel, node.lineno, "key-size-unresolved",
                                            f"`{_src(node, self.lines)}`: RSA key size is not known statically"))
        elif f.primitive == "ecdsa":
            skey, spec = self.match_api(EC_CURVE_ARG, lit, canon)
            if not spec:
                return
            arg = _arg(node, spec[0], spec[1])
            if arg is None:
                return
            name = None
            if isinstance(arg, ast.Call):
                name = _dotted_name(arg.func)
            else:
                name = _dotted_name(arg)
            bits = None
            if name:
                m = re.search(r"(\d{3})", name)
                if m:
                    bits = int(m.group(1))
            if bits:
                f.curve, f.curve_bits = name.split(".")[-1], bits
                f.trail.append(("param", node.lineno, f"curve `{f.curve}` is a {bits}-bit curve (about {bits // 2}-bit security)"))
                if bits < 224:
                    self.emit(node, "weak_key", "proven", f.api,
                              [("call", node.lineno, f"`{_src(node, self.lines)}` generates an EC key"),
                               ("param", node.lineno, f"curve `{f.curve}` gives about {bits // 2}-bit security, below the 112-bit minimum")],
                              curve=f.curve, curve_bits=bits)
            else:
                self.blind.append(BlindSpot(self.rel, node.lineno, "curve-unresolved",
                                            f"`{_src(node, self.lines)}`: elliptic curve is not known statically"))

    def on_attr(self, node):
        if _match_suffix(_dotted_name(node), ECB_ATTR_SUFFIXES):
            d = _dotted_name(node)
            canon, imp = self.canon(d)
            trail = [("attr", node.lineno, f"`{d}` selects ECB mode")]
            if imp and canon != d:
                trail.insert(0, ("import", imp[1], f"`{d}` resolves to `{canon}` through the import on line {imp[1]}"))
            if d.split(".")[-1] == "MODE_ECB" and "const:MODE_ECB" in self.repo_funcs:
                trail.append(("note", node.lineno, "this repository defines `MODE_ECB` itself, so it implements cipher modes; "
                              "AEAD and MAC modes (GCM, SIV, XTS, CMAC, key wrap) are built from the raw block cipher in ECB"))
                self.emit(node, "ecb_mode", "probable", canon or d, trail, benign=True, context="building-block")
                return
            self.emit(node, "ecb_mode", "proven" if d.split(".")[0] in self.imports else "probable", canon or d, trail)

    def on_assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            if len(value) >= SECRET_MIN_LEN and _secret_value(value):
                for target in node.targets:
                    name = target.id if isinstance(target, ast.Name) else None
                    if name and _secret_name(name) and any(h in name.lower() for h in SECRET_NAME_HINTS):
                        hit = [h for h in SECRET_NAME_HINTS if h in name.lower()][0]
                        trail = [("assign", node.lineno,
                                  f"`{name}` is set to a {len(value)}-character string literal"),
                                 ("heuristic", node.lineno,
                                  f"the name contains '{hit}' and the value is at least {SECRET_MIN_LEN} characters")]
                        self.emit(node, "hardcoded_key", "heuristic", name, trail)
                        break

    def on_annassign(self, node):
        if node.value is not None and isinstance(node.target, ast.Name) \
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) \
                and len(node.value.value) >= SECRET_MIN_LEN and _secret_value(node.value.value) \
                and _secret_name(node.target.id) and any(h in node.target.id.lower() for h in SECRET_NAME_HINTS):
            hit = [h for h in SECRET_NAME_HINTS if h in node.target.id.lower()][0]
            trail = [("assign", node.lineno, f"`{node.target.id}` is set to a {len(node.value.value)}-character string literal"),
                     ("heuristic", node.lineno, f"the name contains '{hit}' and the value is at least {SECRET_MIN_LEN} characters")]
            self.emit(node, "hardcoded_key", "heuristic", node.target.id, trail)

    def link_sinks(self):
        """A literal assigned to a variable and later passed to a key sink
        upgrades the name-based guess to proven; otherwise it stands alone."""
        by_line = {}
        for f in self.findings:
            if f.primitive == "hardcoded_key":
                by_line.setdefault(f.line, f)
        for assign_line, api, call_line, trail in self.sink_hits:
            f = by_line.get(assign_line)
            if f is not None:
                f.confidence = "proven"
                f.trail.append(("sink", call_line, f"it reaches `{api}` on line {call_line}, so it is used as a key"))
            else:
                last = trail[-1] if trail else None
                f2 = Finding(file=self.rel, line=call_line, primitive="hardcoded_key",
                             snippet=self.snippet(call_line), confidence="proven", scope=self.scope,
                             api=api, trail=list(trail))
                self.findings.append(f2)


def _show(v):
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    if isinstance(v, str):
        return "'" + (v if len(v) <= 24 else v[:21] + "…") + "'"
    return str(v)


# ------------------------------------------------------------ directory

def _collect_defs(tree, classes, funcs):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MODE_ECB" for t in node.targets):
            funcs.add("const:MODE_ECB")
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "MODE_ECB":
            funcs.add("const:MODE_ECB")
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.add(node.name)
    # top-level and class-level functions both count as definitions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.add(node.name)


def _parse(path, rel):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return source, ast.parse(source, filename=rel), None
    except (SyntaxError, ValueError) as e:
        return source, None, f"{type(e).__name__}: {e.msg if hasattr(e, 'msg') else e}"


def _reachability(parsed, findings):
    """Name-based reachability. Which findings sit in code something can call?

    Roots are import-time code and public API (a top-level function or a method of
    a public class, not starting with an underscore). A private function is
    reached only if reachable code refers to its name. Tests do not count as
    callers. Names are matched without types, so this over-approximates
    reachability: it can miss dead code, but a finding it calls unreferenced
    has no visible caller anywhere in the repository."""
    from collections import deque
    funcs, by_name, fwd, mod_refs, ranges = {}, {}, {}, set(), {}
    for rel, source, tree in parsed:
        scope = file_scope(rel)
        parents = {}
        for n in ast.walk(tree):
            for ch in ast.iter_child_nodes(n):
                parents[ch] = n

        def inner(node):
            p = parents.get(node)
            while p is not None:
                if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return p
                p = parents.get(p)
            return None
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = (rel, n.lineno)
                par = parents.get(n)
                cls = par if isinstance(par, ast.ClassDef) else None
                priv = n.name.startswith("_") and not (n.name.startswith("__") and n.name.endswith("__"))
                public = inner(n) is None and not priv and not (cls is not None and cls.name.startswith("_"))
                funcs[key] = dict(name=n.name, public=public, scope=scope)
                by_name.setdefault(n.name, []).append(key)
                ranges.setdefault(rel, []).append((n.lineno, getattr(n, "end_lineno", n.lineno), key))
            if scope == "test":
                continue
            nm = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else None
            if nm:
                f = inner(n)
                if f is None:
                    mod_refs.add(nm)
                else:
                    fwd.setdefault((rel, f.lineno), set()).add(nm)
    via, q = {}, deque()
    for k, m in funcs.items():
        if m["public"] and m["scope"] != "test":
            via[k] = ("public", None)
            q.append(k)
    for nm in sorted(mod_refs):
        for k in by_name.get(nm, []):
            if k not in via and funcs[k]["scope"] != "test":
                via[k] = ("import-time", nm)
                q.append(k)
    while q:
        k = q.popleft()
        for nm in sorted(fwd.get(k, ())):
            for t in by_name.get(nm, []):
                if t not in via:
                    via[t] = ("called", funcs[k]["name"])
                    q.append(t)
    for f in findings:
        if f.scope == "test":
            f.reach, f.reach_note = "test", "this is test code, so it does not ship"
            continue
        cands = [r for r in ranges.get(f.file, []) if r[0] <= f.line <= r[1]]
        if not cands:
            f.reach, f.reach_note = "import-time", "at module or class level, so it runs when the file is imported"
            continue
        key = min(cands, key=lambda r: r[1] - r[0])[2]
        name = funcs[key]["name"]
        v = via.get(key)
        if v is None:
            f.reach = "unreferenced"
            f.reach_note = (f"`{name}` is not public API and nothing in this repository refers to it, "
                            "so it may be dead code or only reached dynamically")
        elif v[0] == "public":
            f.reach = "public-api"
            f.reach_note = f"`{name}` is public API, so anything that imports this package can reach it"
        elif v[0] == "import-time":
            f.reach = "reached"
            f.reach_note = f"`{name}` is referenced by module-level code, which runs on import"
        else:
            f.reach = "reached"
            f.reach_note = f"`{name}` is reached from `{v[1]}`, which is reachable"


def scan_directory(root_dir):
    """Scan every .py file under root_dir.
    Returns (findings, blind_spots, coverage); paths are relative to root_dir."""
    cov = Coverage()
    parsed = []
    classes, funcs = set(), set()
    blind = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames.sort()
        for fname in sorted(filenames):
            ext = os.path.splitext(fname)[1].lower()
            if ext in OTHER_LANG_EXT:
                cov.other_language_files += 1
            if ext != ".py":
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root_dir)
            cov.files_total += 1
            source, tree, err = _parse(full, rel)
            if tree is None:
                cov.files_failed += 1
                blind.append(BlindSpot(rel, 0, "file-unparseable", f"the file could not be parsed ({err}); it was not scanned"))
                continue
            cov.files_parsed += 1
            cov.loc += len(source.splitlines())
            _collect_defs(tree, classes, funcs)
            parsed.append((rel, source, tree))
    findings = []
    for rel, source, tree in parsed:
        fs = _FileScan(rel, source, tree, (classes, funcs))
        f, b = fs.run()
        findings.extend(f)
        blind.extend(b)
    _reachability(parsed, findings)
    return findings, blind, cov
