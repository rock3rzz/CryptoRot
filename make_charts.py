import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ACCENT = "#2452FF"
AMBER = "#C9A227"
GREEN = "#2E8B57"
GREY = "#999999"

summary = json.load(open("repo_summary.json"))
repos = list(summary.keys())

# ---- Chart 1: classical vs quantum findings per repo ----
fig, ax = plt.subplots(figsize=(6.4, 3.6), dpi=200)
x = range(len(repos))
classical = [summary[r]["classical"] for r in repos]
quantum = [summary[r]["quantum"] for r in repos]
width = 0.35
ax.bar([i - width/2 for i in x], classical, width, label="Classically broken", color="#D64545")
ax.bar([i + width/2 for i in x], quantum, width, label="Quantum-vulnerable", color=ACCENT)
ax.set_xticks(list(x))
ax.set_xticklabels(repos)
ax.set_ylabel("Findings")
ax.set_title("Findings by category, per repository (real scan)")
ax.legend(frameon=False)
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
plt.tight_layout()
plt.savefig("diagrams/findings_by_repo.png", facecolor="white")
plt.close()

# ---- Chart 2: hardcoded_key triage breakdown ----
triage = json.load(open("hardcoded_key_triage.json"))
counts = {}
for v in triage.values():
    counts[v] = counts.get(v, 0) + 1
labels_map = {
    "real_key_fixture": "Real key/secret material\n(hardcoded test fixture)",
    "jwt_test_fixture": "JWT test-token string\n(assigned to a token-like name)",
    "header_stub_only": "PEM header fragment / malformed JSON\n(no real key material)",
}
labels = [labels_map[k] for k in counts]
values = [counts[k] for k in counts]
colors = ["#2E8B57", ACCENT, "#999999"]

fig, ax = plt.subplots(figsize=(6.4, 3.4), dpi=200)
bars = ax.barh(labels, values, color=colors)
ax.set_xlabel("Count (of 54 hardcoded_key findings)")
ax.set_title("Manual triage of every hardcoded-key finding\n(all 3 repos, 100% reviewed)")
for b, v in zip(bars, values):
    ax.text(b.get_width() + 0.5, b.get_y() + b.get_height()/2, str(v), va="center", fontsize=10)
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
plt.tight_layout()
plt.savefig("diagrams/triage_breakdown.png", facecolor="white")
plt.close()

print("charts written")
