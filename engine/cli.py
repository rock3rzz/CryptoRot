import argparse
import itertools
import json
import os
import sys
import textwrap
import time

import report as rpt
from model import CLOCK_LABEL, SOURCES

__version__ = rpt.VERSION

BANNER = r"""  ____ ______   ______ _____ ___  ____   ___ _____
 / ___|  _ \ \ / /  _ \_   _/ _ \|  _ \ / _ \_   _|
| |   | |_) \ V /| |_) || || | | | |_) | | | || |
| |___|  _ < | | |  __/ | || |_| |  _ <| |_| || |
 \____|_| \_\|_| |_|    |_| \___/|_| \_\\___/ |_| """


class _C:
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"; CYAN = "\033[96m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


CLOCK_COLOR = {"now": _C.RED, "policy": _C.YELLOW, "quantum": _C.CYAN, "benign": _C.DIM}


def _banner(color):
    if color:
        print(f"{_C.CYAN}{BANNER}{_C.RESET}")
        print(f"        {_C.DIM}evidence-graded crypto-agility debt scanner  v{__version__}{_C.RESET}")
    else:
        print(BANNER)
        print(f"        evidence-graded crypto-agility debt scanner  v{__version__}")
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


def _wrap(text, indent="      "):
    return "\n".join(textwrap.wrap(text, width=84, initial_indent=indent, subsequent_indent=indent + "     "))


def _due(r):
    if r["clock"] == "benign":
        return "  -  "
    return "TODAY" if r["due"] is None else str(r["due"])


def _print_table(rows, color, show_tests):
    shown = [r for r in rows if show_tests or r["scope"] == "source"]
    hidden = len(rows) - len(shown)
    head = f"{'Due':<6}{'Clock':<9}{'Finding':<30}{'Conf':<10}{'Scope':<8}Location"
    print(head)
    print("-" * 96)
    for r in shown:
        c = CLOCK_COLOR[r["clock"]] if color else ""
        z = _C.RESET if color else ""
        print(f"{c}{_due(r):<6}{r['clock']:<9}{z}{r['title']:<30}{r['confidence']:<10}{r['scope']:<8}{r['file']}:{r['line']}")
    if hidden:
        print(f"\n  ({hidden} findings in tests and examples hidden; rerun with --tests to include them)")


def _print_summary(rep, elapsed, color):
    s = rep["summary"]["by_clock_source"]
    b, z = (_C.BOLD, _C.RESET) if color else ("", "")
    cov = rep["coverage"]
    nsrc = sum(s.values())
    print()
    print(f"{b}Summary{z}: {nsrc} findings in shipped code  "
          f"{s.get('now', 0)} broken today, {s.get('policy', 0)} standards deadline, "
          f"{s.get('quantum', 0)} quantum-vulnerable, {s.get('benign', 0)} declared non-security  "
          f"({elapsed:.2f}s)")
    extra = rep["summary"]["total"] - nsrc
    if extra:
        print(f"         plus {extra} more in tests and examples")
    print(f"Coverage: {cov['files_parsed']}/{cov['files_total']} Python files parsed, {cov['loc']:,} lines"
          + (f", {cov['files_failed']} could not be parsed" if cov["files_failed"] else "")
          + (f"; {cov['other_language_files']} files in other languages were not scanned" if cov["other_language_files"] else ""))
    bs = rep["blind_spots"]
    if bs:
        from collections import Counter
        kinds = Counter(x["kind"] for x in bs)
        print(f"Blind spots: {len(bs)} the scanner could not resolve ("
              + ", ".join(f"{n} {k}" for k, n in kinds.most_common()) + ")  -- see --blind")
    else:
        print("Blind spots: none")


def _print_trails(rows, color, show_tests, limit):
    shown = [r for r in rows if show_tests or r["scope"] == "source"]
    b, z, d = (_C.BOLD, _C.RESET, _C.DIM) if color else ("", "", "")
    print()
    print(f"{b}{'=' * 96}{z}")
    print(f"{b}PROOF TRAILS{z}  how each finding was established, step by step")
    print(f"{b}{'=' * 96}{z}")
    for r in shown[:limit]:
        c = CLOCK_COLOR[r["clock"]] if color else ""
        print(f"\n{c}[{_due(r)}] {r['title']}{z}  {r['file']}:{r['line']}  ({r['confidence']}, {r['scope']}, {r['role']})")
        print(f"      {d}{r['snippet']}{z}" if color else f"      {r['snippet']}")
        for t in r["trail"]:
            ln = f"L{t['line']}" if t["line"] else "   "
            print(_wrap(f"{ln:<5}{t['text']}", indent="      "))
        if r["clock"] != "benign":
            print(_wrap("Fix: " + r["fix"], indent="      "))
        print(f"      Sources: " + ", ".join(r["sources"]) if r["sources"] else "")
    if len(shown) > limit:
        print(f"\n  ... {len(shown) - limit} more; use --trail-all to print every trail")


def _print_blind(rep):
    print("\nBLIND SPOTS  (not findings; places the scanner could not see through)")
    for x in rep["blind_spots"]:
        print(f"  {x['file']}:{x['line']}  [{x['kind']}]  {x['detail']}")


def _run_selftest(color):
    import selftest
    rows, s = selftest.evaluate(selftest.scan_v04)
    b, z = (_C.BOLD, _C.RESET) if color else ("", "")
    print(f"{b}Self-test: mutation testing of the scanner{z}")
    fams = {}
    for r in rows:
        fams.setdefault(r["family"], []).append(r)
    for fam, rs in fams.items():
        ok = sum(1 for r in rs if r["state"] in ("detected", "declared", "pass"))
        print(f"  {fam:<22}{ok}/{len(rs)}")
    print(f"\n  {s['mutants']} rewritten misuses: {s['detected']} detected, {s['declared']} declared as blind spots, "
          f"{s['missed']} silently missed")
    print(f"  {s['controls']} safe-code controls: {s['false_positives']} false positives")
    return 0 if s["missed"] == 0 and s["false_positives"] == 0 else 1


def build_parser():
    p = argparse.ArgumentParser(
        prog="cryptorot",
        description=("Find crypto-agility debt in Python code. Every finding is placed on a dated "
                     "clock (broken today, standards deadline, quantum) and carries a proof trail."))
    p.add_argument("target", nargs="?", help="directory to scan")
    p.add_argument("-o", "--json", metavar="FILE", help="write the full JSON report to FILE")
    p.add_argument("--cbom", metavar="FILE", help="write a CycloneDX 1.6 CBOM to FILE")
    p.add_argument("--sarif", metavar="FILE", help="write a SARIF 2.1.0 report to FILE")
    p.add_argument("--fail-on", choices=["now", "policy", "quantum"], metavar="CLOCK",
                   help="exit 1 if any source-code finding is on this clock or an earlier one (CI gate)")
    p.add_argument("--tests", action="store_true", help="include findings in tests and examples")
    p.add_argument("--trail", action="store_true", help="print the proof trail for each finding")
    p.add_argument("--trail-all", action="store_true", help="print every proof trail")
    p.add_argument("--blind", action="store_true", help="list every blind spot")
    p.add_argument("--selftest", action="store_true", help="mutation-test the scanner itself")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    tty = sys.stdout.isatty()
    color = tty and not args.no_color

    if args.selftest:
        return _run_selftest(color)
    if not args.target:
        print("cryptorot: error: a target directory is required", file=sys.stderr)
        return 2
    if not os.path.isdir(args.target):
        print(f"cryptorot: error: '{args.target}' is not a directory", file=sys.stderr)
        return 2

    if not args.quiet:
        _banner(color)
        _spin(f"Scanning {args.target}", 1.0, tty)
    t0 = time.time()
    rep = rpt.analyze(args.target)
    elapsed = time.time() - t0

    if not args.quiet:
        rows = rep["findings"]
        if rows:
            _print_table(rows, color, args.tests)
        else:
            print("No known-vulnerable cryptographic primitives detected.")
        _print_summary(rep, elapsed, color)
        if args.trail or args.trail_all:
            _print_trails(rows, color, args.tests, 10 ** 9 if args.trail_all else 8)
        if args.blind:
            _print_blind(rep)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(rpt.to_json(rep))
    if args.cbom:
        with open(args.cbom, "w", encoding="utf-8") as f:
            json.dump(rpt.to_cbom(rep, os.path.basename(os.path.abspath(args.target))), f, indent=2)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            json.dump(rpt.to_sarif(rep), f, indent=2)

    if args.fail_on:
        order = ["now", "policy", "quantum"]
        gate = set(order[: order.index(args.fail_on) + 1])
        if any(r["clock"] in gate and r["scope"] == "source" for r in rep["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
