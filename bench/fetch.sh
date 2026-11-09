#!/bin/sh
# Clones every benchmark project at its pinned commit into bench/repos/.
# python-rsa is also cloned with full history for the release timeline.
set -e
cd "$(dirname "$0")"
mkdir -p repos
python3 - <<'PY'
import json, os, subprocess
for p in json.load(open("pins.json")):
    d = os.path.join("repos", p["name"])
    if os.path.isdir(d):
        continue
    os.makedirs(d)
    run = lambda *a: subprocess.run(["git", "-C", d, *a], check=True)
    run("init", "-q")
    run("remote", "add", "origin", p["url"])
    run("fetch", "-q", "--depth", "1", "origin", p["commit"])
    run("checkout", "-q", "FETCH_HEAD")
    print("pinned", p["name"], p["commit"][:7])
PY
[ -d repos/python-rsa-history ] || git clone -q https://github.com/sybrenstuvel/python-rsa repos/python-rsa-history
