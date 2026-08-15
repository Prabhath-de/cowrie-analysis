"""
acl_generator_final.py

This stage never existed as a saved script anywhere in the repo (confirmed:
`grep -rl "cisco_acl_candidates" --include="*.py"` returns nothing) -- your
existing cisco_acl_candidates_v1.csv/.txt were produced some other way and
never committed. This rebuilds it as reusable code, matching the exact
format of your existing output (verified field-for-field against the
sample rows you showed me).

Only reads mitigation_decision_OLD (the validated, unchanged 0-15-scale
decision) to decide what actually gets enforced. mitigation_decision_new
(patched severity scale) is reported separately as a "would additionally
block" list -- visible, not silently enforced, per the same reasoning as
temporal_decision_final.py.

Input:
    scoring/temporal_decision_final.csv

Outputs:
    scoring/cisco_acl_candidates_final.csv
    scoring/cisco_acl_candidates_final.txt
    scoring/cisco_acl_candidates_new_signal_review.csv   -- diagnostic only,
        IPs that only qualify once the backdoor/dropper patch is counted
"""

import csv

INPUT = "scoring/temporal_decision_final.csv"

OUT_CSV = "scoring/cisco_acl_candidates_final.csv"
OUT_TXT = "scoring/cisco_acl_candidates_final.txt"
OUT_REVIEW_CSV = "scoring/cisco_acl_candidates_new_signal_review.csv"

ACL_NAME = "COWRIE_DYNAMIC_BLOCK"


def make_acl_rule(ip):
    return f" deny tcp host {ip} any eq 22"


rows = []
with open(INPUT, newline="", errors="ignore") as fh:
    for row in csv.DictReader(fh):
        rows.append(row)

# ------------------------------------------------------------
# Validated ACL candidates -- mitigation_decision_old only
# ------------------------------------------------------------

block_rows = [r for r in rows if r["mitigation_decision_old"] == "ACL_BLOCK_CANDIDATE"]
block_rows.sort(key=lambda r: float(r["total_old"]), reverse=True)

csv_rows = []
for r in block_rows:
    csv_rows.append({
        "ip": r["ip"],
        "score": f"{float(r['total_old']):.4f}",
        "risk": r["risk_level_old"],
        "temporal": r["temporal_level"],
        "burst": r["burst_10plus_5s"],
        "acl_action": "DENY_SSH",
        "acl_rule": make_acl_rule(r["ip"]).strip(),
    })

with open(OUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["ip", "score", "risk", "temporal", "burst", "acl_action", "acl_rule"])
    writer.writeheader()
    writer.writerows(csv_rows)

txt_lines = [
    "!",
    "! COWRIE DYNAMIC SSH DEFENSE",
    "!",
    f"ip access-list extended {ACL_NAME}",
]
for r in block_rows:
    txt_lines.append(make_acl_rule(r["ip"]))
txt_lines.append(" permit ip any any")
txt_lines.append("!")

with open(OUT_TXT, "w") as f:
    f.write("\n".join(txt_lines) + "\n")


# ------------------------------------------------------------
# Diagnostic: IPs that ONLY qualify once the backdoor/dropper
# patch is counted (mitigation_decision_new says block, old
# doesn't). NOT written into the enforced ACL -- for review.
# ------------------------------------------------------------

review_rows = [
    r for r in rows
    if r["mitigation_decision_new"] == "ACL_BLOCK_CANDIDATE"
    and r["mitigation_decision_old"] != "ACL_BLOCK_CANDIDATE"
]
review_rows.sort(key=lambda r: float(r["total_new"]), reverse=True)

with open(OUT_REVIEW_CSV, "w", newline="") as f:
    fields = ["ip", "total_old", "total_new", "mitigation_decision_old", "mitigation_decision_new",
              "persistence_backdoor_hits", "dropper_execution_hits", "temporal_level"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for r in review_rows:
        writer.writerow({k: r[k] for k in fields})


# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

print("=" * 70)
print("CISCO ACL CANDIDATES -- FINAL")
print("=" * 70)
print()
print(f"Enforced ACL entries (validated, mitigation_decision_old): {len(block_rows)}")
print(f"Additional review candidates (new-signal only, NOT enforced): {len(review_rows)}")
print()
print("Preview of enforced ACL:")
print("\n".join(txt_lines[:10]))
print()
if review_rows:
    print("IPs held back for review pending threshold recalibration:")
    for r in review_rows[:15]:
        print(
            f"  {r['ip']:18s} total_old={float(r['total_old']):.2f} total_new={float(r['total_new']):.2f} "
            f"backdoor={r['persistence_backdoor_hits']} dropper={r['dropper_execution_hits']}"
        )
print()
print(f"Created: {OUT_CSV}")
print(f"Created: {OUT_TXT}")
print(f"Created: {OUT_REVIEW_CSV}")
