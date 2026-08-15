"""
check_old_decision.py

Checks which of the original 11 ACL_BLOCK_CANDIDATE IPs (from the
FROZEN/unchanged mitigation_decision_old) still show up correctly.
mitigation_decision_old should NEVER change between runs, since its
inputs (total_old, temporal) and logic were never modified. If any of
these 11 no longer shows ACL_BLOCK_CANDIDATE, this prints exactly why.
"""

import csv

original_11 = [
    "35.229.125.98", "34.75.237.227", "34.139.191.163", "136.107.187.197",
    "128.1.44.162", "34.150.142.107", "34.138.181.9", "158.180.79.132",
    "182.93.7.194", "136.232.11.10", "106.251.244.178",
]

rows = {}
with open("scoring/temporal_decision_final.csv", newline="") as f:
    for row in csv.DictReader(f):
        rows[row["ip"]] = row

print(f"{'ip':<18}{'total_old':>10}{'temporal':>14}{'mitigation_decision_old':>28}")
print("-" * 72)
mismatch_count = 0
for ip in original_11:
    r = rows.get(ip)
    if r is None:
        print(f"{ip:<18}  NOT FOUND IN CSV AT ALL")
        mismatch_count += 1
        continue
    decision = r["mitigation_decision_old"]
    flag = "" if decision == "ACL_BLOCK_CANDIDATE" else "  <-- MISMATCH"
    if flag:
        mismatch_count += 1
    print(f"{ip:<18}{float(r['total_old']):>10.4f}{r['temporal_level']:>14}{decision:>28}{flag}")

print()
print(f"Total mismatches: {mismatch_count} out of {len(original_11)}")

# also cross-check against post_auth_combined_final.csv directly, in case
# temporal_decision_final.csv itself is stale relative to it
print()
print("=== Cross-check against post_auth_combined_final.csv directly ===")
combined = {}
with open("scoring/post_auth_combined_final.csv", newline="") as f:
    for row in csv.DictReader(f):
        combined[row["ip"]] = row

for ip in original_11:
    c = combined.get(ip)
    if c is None:
        print(f"{ip:<18}  NOT FOUND in post_auth_combined_final.csv")
        continue
    print(f"{ip:<18} total_old={float(c['total_old']):.4f}  risk_level_old={c['risk_level_old']}")
