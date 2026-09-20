"""
CryptoRot debt scorer.
Implements the Phase 1 formula unchanged:
    debt_score = min(100, base_severity * path_multiplier * frequency_multiplier)
Each finding gets exactly one path multiplier and one frequency multiplier.
"""
from collections import Counter
from rules import RULES, SECURITY_PATH_HINTS, TEST_PATH_HINTS
def path_multiplier(file_path):
    lowered = file_path.lower()
    # Test discount wins over the security bump if both match.
    if any(h in lowered for h in TEST_PATH_HINTS):
        return 0.5
    if any(h in lowered for h in SECURITY_PATH_HINTS):
        return 1.5
    return 1.0
def frequency_multiplier(count_for_primitive_in_repo):
    if count_for_primitive_in_repo >= 6:
        return 1.3
    if count_for_primitive_in_repo >= 2:
        return 1.15
    return 1.0
def score_findings(findings):
    """Takes a list of ast_scanner.Finding, returns a list of scored dicts,
    sorted by debt_score descending (highest migration urgency first)."""
    primitive_counts = Counter(f.primitive for f in findings)
    scored = []
    for f in findings:
        category, base_severity, human_name, remediation = RULES[f.primitive]
        pm = path_multiplier(f.file)
        fm = frequency_multiplier(primitive_counts[f.primitive])
        debt_score = min(100, round(base_severity * pm * fm, 1))
        scored.append(
            {
                "file": f.file,
                "line": f.line,
                "primitive": f.primitive,
                "human_name": human_name,
                "category": category,
                "snippet": f.snippet,
                "base_severity": base_severity,
                "path_multiplier": pm,
                "frequency_multiplier": fm,
                "debt_score": debt_score,
                "remediation": remediation,
            }
        )
    scored.sort(key=lambda r: r["debt_score"], reverse=True)
    return scored
def path_multiplier_tag(file_path):
    """Short matched keyword for display (e.g. 'auth', 'test'), or None
    if no path adjustment applied. Mirrors path_multiplier()'s decision
    exactly, kept separate so the validated scoring function is untouched."""
    lowered = file_path.lower()
    for h in TEST_PATH_HINTS:
        if h in lowered:
            return h
    for h in SECURITY_PATH_HINTS:
        if h in lowered:
            return h
    return None
