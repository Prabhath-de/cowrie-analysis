"""
threshold_analysis_new.py

Re-derives the empirical percentile thresholds against total_new
(post-patch, backdoor/dropper signal included), the same exercise
already done against total_old -- now that total_new actually carries
real signal instead of being identical to total_old due to the parser
bug.

Run this AFTER post_auth_scoring_final.py and temporal_decision_final.py
have both been re-run with the fixed parser output.
"""

import csv
import statistics

rows = []
with open("scoring/temporal_decision_final.csv", newline="") as f:
    for row in csv.DictReader(f):
        rows.append(row)

total_new = sorted(float(r["total_new"]) for r in rows)
total_old = sorted(float(r["total_old"]) for r in rows)


def pct(values, p):
    if not values:
        return 0
    i = (len(values) - 1) * p / 100
    lo = int(i)
    hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (i - lo)


print("=" * 80)
print("THRESHOLD COMPARISON: total_old (buggy) vs total_new (fixed)")
print("=" * 80)
print()
print(f"{'Percentile':<12}{'total_old':>12}{'total_new':>12}")
for p in [50, 75, 90, 95, 97, 98, 99, 99.5, 99.9]:
    print(f"P{p:<11}{pct(total_old, p):>12.4f}{pct(total_new, p):>12.4f}")

print()
print(f"{'min':<12}{min(total_old):>12.4f}{min(total_new):>12.4f}")
print(f"{'max':<12}{max(total_old):>12.4f}{max(total_new):>12.4f}")
print(f"{'mean':<12}{statistics.mean(total_old):>12.4f}{statistics.mean(total_new):>12.4f}")

new_p995 = pct(total_new, 99.5)

print()
print("=" * 80)
print(f"PROPOSED NEW FINAL THRESHOLD: total_new >= {new_p995:.4f} (P99.5 of total_new)")
print("=" * 80)

burst_threshold = 10
candidates = [
    r for r in rows
    if float(r["total_new"]) >= new_p995 and int(float(r["burst_10plus_5s"])) >= burst_threshold
]
candidates.sort(key=lambda r: float(r["total_new"]), reverse=True)

print(f"\nCandidates under NEW threshold (score>={new_p995:.4f} AND burst>={burst_threshold}): {len(candidates)}")
print()
print(f"{'ip':<18}{'total_old':>10}{'total_new':>10}{'backdoor':>10}{'dropper':>9}{'burst':>7}")
for r in candidates:
    print(
        f"{r['ip']:<18}{float(r['total_old']):>10.2f}{float(r['total_new']):>10.2f}"
        f"{int(r['persistence_backdoor_hits']):>10}{int(r['dropper_execution_hits']):>9}"
        f"{int(float(r['burst_10plus_5s'])):>7}"
    )

# Compare to the old rule's candidate set for a clear diff
old_threshold = 6.8918
old_candidates = set(
    r["ip"] for r in rows
    if float(r["total_old"]) >= old_threshold and int(float(r["burst_10plus_5s"])) >= burst_threshold
)
new_candidates = set(r["ip"] for r in candidates)

print()
print(f"Old rule (total_old>={old_threshold}, burst>={burst_threshold}): {len(old_candidates)} IPs")
print(f"New rule (total_new>={new_p995:.4f}, burst>={burst_threshold}): {len(new_candidates)} IPs")
print(f"Added by new rule   : {sorted(new_candidates - old_candidates)}")
print(f"Removed by new rule : {sorted(old_candidates - new_candidates)}")
