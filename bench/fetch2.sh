#!/bin/sh
# Round 2: clones the 20 additional projects at their pinned commits into bench/repos2/.
set -e
cd "$(dirname "$0")"
mkdir -p repos2
python3 - <<'PY'
import json, os, subprocess
for p in json.load(open("pins2.json")):
    d = os.path.join("repos2", p["name"])
    if os.path.isdir(d):
        continue
    os.makedirs(d)
    run = lambda *a: subprocess.run(["git", "-C", d, *a], check=True)
    run("init", "-q"); run("remote", "add", "origin", p["url"])
    run("fetch", "-q", "--depth", "1", "origin", p["commit"]); run("checkout", "-q", "FETCH_HEAD")
    print("pinned", p["name"], p["commit"][:7])
PY
