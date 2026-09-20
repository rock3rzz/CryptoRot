import argparse
import itertools
import json
import os
import shutil
import sys
import textwrap
import time
from collections import Counter
from ast_scanner import scan_directory
from scorer import score_findings, path_multiplier_tag
from rules import PLAIN_EXPLANATIONS, HOW_IT_BREAKS
__version__ = "0.3.0"
BANNER = r"""  ____ ______   ______ _____ ___  ____   ___ _____ 
 / ___|  _ \ \ / /  _ \_   _/ _ \|  _ \ / _ \_   _|
| |   | |_) \ V /| |_) || || | | | |_) | | | || |  
| |___|  _ < | | |  __/ | || |_| |  _ <| |_| || |  
 \____|_| \_\|_| |_|    |_| \___/|_| \_\\___/ |_|  """
# Recomputed in main() from the real terminal width -- 78 is just the
# fallback used when width can't be detected (e.g. output piped to a file).
CARD_WIDTH = 78
class _Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
def _print_banner(use_color):
    if use_color:
        print(f"{_Colors.CYAN}{BANNER}{_Colors.RESET}")
        print(f"        {_Colors.RED}[ ! ] rot detected{_Colors.RESET} --> scored --> "
              f"{_Colors.GREEN}[ v ] cleaned{_Colors.RESET}")
        print(f"        {_Colors.DIM}AST-based crypto-agility debt scanner  v{__version__}{_Colors.RESET}")
    else:
        print(BANNER)
        print("        [ ! ] rot detected --> scored --> [ v ] cleaned")
        print(f"        AST-based crypto-agility debt scanner  v{__version__}")
    print()
def _spin(label, seconds, animate):
    if not animate:
        print(f"{label} ...")
        return
    frames = "|/-\\"
    end = time.time() + seconds
    for i in itertools.count():
        if time.time() >= end:
            break
        sys.stdout.write(f"\r{label} ... {frames[i % len(frames)]}")
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write("\r" + " " * (len(label) + 8) + "\r")
    sys.stdout.flush()
def _severity(score):
    if score >= 80:
        return "CRITICAL", _Colors.RED
    if score >= 50:
        return "MEDIUM", _Colors.YELLOW
    return "LOW", _Colors.GREEN
def _print_table(scored, use_color):
    header = f"   {'Score':>6}  {'Primitive':<26}{'Category':<11}Location"
    print(header)
    print("-" * max(len(header), 80))
    for r in scored:
        loc = f"{r['file']}:{r['line']}"
        _, color = _severity(r["debt_score"])
        dot = f"{color}\u25cf{_Colors.RESET}" if use_color else "*"
        score_str = f"{r['debt_score']:>6}"
        if use_color:
            score_str = f"{color}{score_str}{_Colors.RESET}"
        print(f" {dot} {score_str}  {r['human_name']:<26}{r['category']:<11}{loc}")
def _print_summary(scored, elapsed, use_color):
    classical = sum(1 for r in scored if r["category"] == "classical")
    quantum = sum(1 for r in scored if r["category"] == "quantum")
    critical = sum(1 for r in scored if r["debt_score"] >= 80)
    bold, reset = (_Colors.BOLD, _Colors.RESET) if use_color else ("", "")
    print()
    print(
        f"{bold}Summary{reset}: {len(scored)} findings "
        f"({classical} classically-broken, {quantum} quantum-vulnerable, "
        f"{critical} critical) in {elapsed:.3f}s"
    )
def _seg(text, color, use_color):
    return f"{color}{text}{_Colors.RESET}" if (use_color and color) else text
def _card_line(parts, use_color, indent=2):
    """parts: list of (text, color_or_None). Pads to CARD_WIDTH using the
    VISIBLE text length, then colorizes -- so alignment never breaks."""
    visible = " " * indent + "".join(t for t, _ in parts)
    pad = max(CARD_WIDTH - 2 - len(visible), 0)
    body = " " * indent + "".join(_seg(t, c, use_color) for t, c in parts)
    return f"\u2502{body}{' ' * pad}\u2502"
def _card_top(title, tag, tag_color, use_color):
    left = f"\u250c\u2500 {title} "
    right_plain = f" {tag} \u2500\u2500\u2510"
    dashes = max(CARD_WIDTH - len(left) - len(right_plain), 0)
    right = f" {_seg(tag, tag_color, use_color)} " + "\u2500" * 2 + "\u2510"
    return left + "\u2500" * dashes + right
def _card_bottom():
    return "\u2514" + "\u2500" * (CARD_WIDTH - 2) + "\u2518"
def _truncate(text, width):
    return text if len(text) <= width else text[: width - 3] + "..."
def _print_detailed(scored, use_color):
    if not scored:
        return
    counts = Counter(r["primitive"] for r in scored)
    groups = {}
    for r in scored:
        groups.setdefault(r["primitive"], []).append(r)
    order = sorted(groups.keys(), key=lambda p: max(x["debt_score"] for x in groups[p]), reverse=True)
    bold, reset = (_Colors.BOLD, _Colors.RESET) if use_color else ("", "")
    print(f"\n{bold}DETAILED BREAKDOWN{reset}\n")
    text_width = CARD_WIDTH - 6
    for i, prim in enumerate(order, 1):
        items = groups[prim]
        human_name = items[0]["human_name"]
        remediation = items[0]["remediation"]
        explanation = PLAIN_EXPLANATIONS.get(prim, "")
        breaks_how = HOW_IT_BREAKS.get(prim, "")
        worst = max(x["debt_score"] for x in items)
        count = counts[prim]
        label, color = _severity(worst)
        title = f"[{i}] {human_name}"
        tag = f"{label} \u00b7 x{count}"
        print(_card_top(title, tag, color, use_color))
        print(_card_line([("", None)], use_color))
        for line in textwrap.wrap(explanation, text_width):
            print(_card_line([(line, None)], use_color))
        print(_card_line([("", None)], use_color))
        print(_card_line([("[!] How it breaks:", _Colors.YELLOW)], use_color))
        for line in textwrap.wrap(breaks_how, text_width):
            print(_card_line([(line, None)], use_color))
        print(_card_line([("", None)], use_color))
        fix_lines = textwrap.wrap(remediation, text_width - 5) or [""]
        print(_card_line([("Fix: ", _Colors.BOLD), (fix_lines[0], None)], use_color))
        for line in fix_lines[1:]:
            print(_card_line([("     ", None), (line, None)], use_color))
        print(_card_line([("", None)], use_color))
        print(_card_line([("\u2500" * (CARD_WIDTH - 6), _Colors.DIM)], use_color))
        print(_card_line([("", None)], use_color))
        for idx, r in enumerate(items):
            tag_word = path_multiplier_tag(r["file"])
            tag_str = f"{tag_word}/" if tag_word else "no adjustment"
            print(_card_line([
                ("\u25cf Score: ", color), (str(r["debt_score"]), color),
            ], use_color, indent=4))
            print(_card_line([("", None)], use_color))
            print(_card_line([("File: ", _Colors.BOLD), (r["file"], None)], use_color, indent=6))
            print(_card_line([("Line: ", _Colors.BOLD), (str(r["line"]), None)], use_color, indent=6))
            snippet_lines = textwrap.wrap(r["snippet"], text_width - 8) or [""]
            for j, line in enumerate(snippet_lines):
                label = "Code: " if j == 0 else "      "
                print(_card_line([(label, _Colors.BOLD), (line, None)], use_color, indent=6))
            math_line = f"{r['base_severity']} (base) \u00d7 {r['path_multiplier']} ({tag_str}) \u00d7 {r['frequency_multiplier']} (freq) = {r['debt_score']}"
            print(_card_line([("Why:  ", _Colors.BOLD), (math_line, _Colors.DIM)], use_color, indent=6))
            if idx != len(items) - 1:
                print(_card_line([("", None)], use_color))
                print(_card_line([("", None)], use_color))
        print(_card_line([("", None)], use_color))
        print(_card_bottom())
        print()
def _print_priority(scored, use_color):
    if not scored:
        return
    classical = [r for r in scored if r["category"] == "classical"]
    quantum = [r for r in scored if r["category"] == "quantum"]
    bold, reset = (_Colors.BOLD, _Colors.RESET) if use_color else ("", "")
    print(f"{bold}What to prioritize{reset}")
    if classical:
        print(f"  -> {len(classical)} classical: exploitable TODAY. Fix these first.")
    if quantum:
        print(f"  -> {len(quantum)} quantum: safe today, plan migration ahead of large-scale quantum computers.")
def run(target_dir, json_out=None, use_color=True, quiet=False, animate=False, brief=False):
    if not quiet:
        _spin(f"Scanning {target_dir}", 1.1, animate)
    start = time.time()
    findings = scan_directory(target_dir)
    scored = score_findings(findings)
    elapsed = time.time() - start
    if not quiet:
        if scored:
            _print_table(scored, use_color)
        else:
            print("No known-vulnerable cryptographic primitives detected.")
        _print_summary(scored, elapsed, use_color)
        if not brief:
            _print_detailed(scored, use_color)
            _print_priority(scored, use_color)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(scored, f, indent=2)
        if not quiet:
            print(f"\nFull JSON report written to {json_out}")
    return scored
def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptorot",
        description=(
            "Detect crypto-agility debt in a Python codebase: classically-broken "
            "and quantum-vulnerable cryptographic primitives, AST-detected and "
            "scored by a fixed, recomputable formula."
        ),
    )
    parser.add_argument("target", help="directory to scan")
    parser.add_argument("-o", "--json", metavar="FILE", help="write the full JSON report to FILE")
    parser.add_argument("--min-score", type=float, metavar="N",
                         help="exit with status 1 if any finding scores >= N (CI gate)")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress all output")
    parser.add_argument("--brief", action="store_true", help="show the summary table only, skip the detailed breakdown")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--width", type=int, metavar="N", help="force card width instead of auto-detecting")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser
def main(argv=None):
    global CARD_WIDTH
    args = build_parser().parse_args(argv)
    is_tty = sys.stdout.isatty()
    use_color = is_tty and not args.no_color
    animate = is_tty and not args.quiet
    if args.width:
        CARD_WIDTH = max(50, args.width)
    else:
        term_width = shutil.get_terminal_size(fallback=(78, 24)).columns
        CARD_WIDTH = max(50, min(term_width - 2, 100))
    if not args.quiet:
        _print_banner(use_color)
    if not os.path.exists(args.target):
        print(f"cryptorot: error: '{args.target}' does not exist", file=sys.stderr)
        return 2
    if not os.path.isdir(args.target):
        print(f"cryptorot: error: '{args.target}' is not a directory", file=sys.stderr)
        return 2
    scored = run(args.target, json_out=args.json, use_color=use_color, quiet=args.quiet,
                 animate=animate, brief=args.brief)
    if args.min_score is not None and any(r["debt_score"] >= args.min_score for r in scored):
        return 1
    return 0
if __name__ == "__main__":
    sys.exit(main())
