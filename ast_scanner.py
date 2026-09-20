"""
AST scanner for CryptoRot Phase 2. Python only for now
"""
import ast
import os
import warnings
from dataclasses import dataclass
from rules import (
    CALL_PATTERNS,
    HASHLIB_NEW_ALGOS,
    ECB_ATTR_SUFFIXES,
    SECRET_NAME_HINTS,
)
@dataclass
class Finding:
    file: str
    line: int
    primitive: str
    snippet: str = ""
def _dotted_name(node):
    """Resolve an ast.Attribute/ast.Name chain to a dotted string.
    e.g. Attribute(Attribute(Name('Crypto'),'Hash'),'MD5') -> 'Crypto.Hash.MD5'
    Returns None if the chain contains anything else (call results, etc.)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None
def _call_target_name(call_node):
    """Best-effort dotted name of what's being called, e.g. 'hashlib.md5'."""
    func = call_node.func
    if isinstance(func, ast.Attribute):
        return _dotted_name(func)
    if isinstance(func, ast.Name):
        return func.id
    return None
def _match_suffix(dotted, suffixes):
    if not dotted:
        return False
    tail = dotted.split(".")[-1]
    return tail in suffixes
class _Visitor(ast.NodeVisitor):
    def __init__(self, filename, source_lines):
        self.filename = filename
        self.source_lines = source_lines
        self.findings = []
    def _snippet(self, lineno):
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""
    def _emit(self, lineno, primitive):
        self.findings.append(
            Finding(
                file=self.filename,
                line=lineno,
                primitive=primitive,
                snippet=self._snippet(lineno),
            )
        )
    def visit_Call(self, node):
        # this is where most of the detections happen, things like
        # hashlib.md5(x) or rsa.generate_private_key(...)
        target = _call_target_name(node)
        if target in CALL_PATTERNS:
            self._emit(node.lineno, CALL_PATTERNS[target])
        elif target and target.split(".")[-1] == "new":
            # separate case for hashlib.new("md5", ...), the algorithm
            # name is passed in as a string argument instead of being
            # part of the function name
            root = target.rsplit(".", 1)[0] if "." in target else target
            if root.endswith("hashlib") and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    algo = first.value.lower()
                    if algo in HASHLIB_NEW_ALGOS:
                        self._emit(node.lineno, HASHLIB_NEW_ALGOS[algo])
        self.generic_visit(node)
    def visit_Attribute(self, node):
        # catches AES.MODE_ECB, DES3.MODE_ECB, anything ending in MODE_ECB
        if _match_suffix(_dotted_name(node), ECB_ATTR_SUFFIXES):
            self._emit(node.lineno, "ecb_mode")
        self.generic_visit(node)
    def visit_Assign(self, node):
        # looks for stuff like KEY = "some long string" where the variable
        # name suggests a secret. length cutoff is 12 chars, I had it at 6
        # originally but that flagged keyname = "public" in python-rsa's
        # cli.py as a hardcoded key, which it obviously isn't
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            if len(value) >= 12:
                for target in node.targets:
                    name = target.id if isinstance(target, ast.Name) else None
                    if name and any(h in name.lower() for h in SECRET_NAME_HINTS):
                        self._emit(node.lineno, "hardcoded_key")
                        break
        self.generic_visit(node)
def scan_file(path, rel_path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return []
    visitor = _Visitor(rel_path, source.splitlines())
    visitor.visit(tree)
    return visitor.findings
def scan_directory(root_dir):
    """Scan every .py file under root_dir. Returns a flat list of Findings
    with file paths relative to root_dir."""
    all_findings = []
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, root_dir)
            all_findings.extend(scan_file(full_path, rel_path))
    return all_findings
