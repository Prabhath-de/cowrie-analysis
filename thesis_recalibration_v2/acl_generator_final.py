"""
acl_generator_final.py

This stage never existed as a saved script anywhere in the repo (confirmed:
`grep -rl "cisco_acl_candidates" --include="*.py"` returns nothing) -- your
existing cisco_acl_candidates_v1.csv/.txt were produced some other way and
never committed. This rebuilds it as reusable code, matching the exact
format of your existing output (verified field-for-field against the
sample rows you showed me).

UPDATE (post parser-bug-fix, now official): enforces off
mitigation_decision_NEW -- the corrected 0-18.5 scale score (backdoor/
dropper signal included) combined with the empirically re-derived
FINAL_ACL_SCORE_THRESHOLD (8.5669, P99.5 of total_new) and burst >= 10.
mitigation_decision_old (the original frozen model) is kept in the output
CSV for audit/comparison only -- it no longer drives enforcement.

Input:
    scoring/temporal_decision_final.csv

Outputs:
    scoring/cisco_acl_candidates_final.csv
    scoring/cisco_acl_candidates_final.txt
    scoring/cisco_acl_candidates_dropped_from_old_rule.csv  -- audit trail,
        IPs that WERE ACL_BLOCK_CANDIDATE under the old rule but no longer
        qualify under the corrected score + P99.5 threshold
"""

import csv

INPUT = "scoring/temporal_decision_final.csv"

OUT_CSV = "scoring/cisco_acl_candidates_final.csv"
OUT_TXT = "scoring/cisco_acl_candidates_final.txt"
OUT_DROPPED_CSV = "scoring/cisco_acl_candidates_dropped_from_old_rule.csv"

ACL_NAME = "COWRIE_DYNAMIC_BLOCK"


def make_acl_rule(ip):
    return f" deny tcp host {ip} any eq 22"


rows = []
with open(INPUT, newline="", errors="ignore") as fh:
    for row in csv.DictReader(fh):
        rows.append(row)

# ------------------------------------------------------------
# Enforced ACL candidates -- mitigation_decision_new, the final,
# official rule (corrected score + P99.5 threshold + burst>=10)
# ------------------------------------------------------------

block_rows = [r for r in rows if r["mitigation_decision_new"] == "ACL_BLOCK_CANDIDATE"]
block_rows.sort(key=lambda r: float(r["total_new"]), reverse=True)

csv_rows = []
for r in block_rows:
    csv_rows.append({
        "ip": r["ip"],
        "score": f"{float(r['total_new']):.4f}",
        "risk": r["risk_level_new"],
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
# Audit trail: IPs that WERE ACL_BLOCK_CANDIDATE under the old
# (frozen) rule but no longer qualify under the corrected score
# + P99.5 threshold. Expected and explainable (see conversation
# history / thesis methodology note on distribution shift) --
# not written into the enforced ACL, kept visible for the record.
# ------------------------------------------------------------

dropped_rows = [
    r for r in rows
    if r["mitigation_decision_old"] == "ACL_BLOCK_CANDIDATE"
    and r["mitigation_decision_new"] != "ACL_BLOCK_CANDIDATE"
]
dropped_rows.sort(key=lambda r: float(r["total_new"]), reverse=True)

with open(OUT_DROPPED_CSV, "w", newline="") as f:
    fields = ["ip", "total_old", "total_new", "mitigation_decision_old", "mitigation_decision_new",
              "persistence_backdoor_hits", "dropper_execution_hits", "temporal_level"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for r in dropped_rows:
        writer.writerow({k: r[k] for k in fields})


# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

print("=" * 70)
print("CISCO ACL CANDIDATES -- FINAL")
print("=" * 70)
print()
print(f"Enforced ACL entries (final rule: mitigation_decision_new): {len(block_rows)}")
print(f"Dropped vs. old frozen rule (audit trail, expected due to distribution shift): {len(dropped_rows)}")
print()
print("Preview of enforced ACL:")
print("\n".join(txt_lines[:10]))
print()
if dropped_rows:
    print("IPs that no longer qualify vs. the old frozen model:")
    for r in dropped_rows[:15]:
        print(
            f"  {r['ip']:18s} total_old={float(r['total_old']):.2f} total_new={float(r['total_new']):.2f} "
            f"backdoor={r['persistence_backdoor_hits']} dropper={r['dropper_execution_hits']}"
        )
print()
print(f"Created: {OUT_CSV}")
print(f"Created: {OUT_TXT}")
print(f"Created: {OUT_DROPPED_CSV}")
