"""
temporal_decision_final.py

Consolidates post_auth_temporal_crosscheck_v1.py + post_auth_temporal_decision_v2.py
into one stage. The crosscheck_v1 stage's own temporal_level/decision columns
are dropped -- traced through decision_v2.py's source and confirmed they are
never read for the actual decision, only carried forward unused via
dict(row). temporal_level() and the non-final branch of mitigation_decision()
are copied VERBATIM from post_auth_temporal_decision_v2.py -- same constants
(BURST_MIN=10, HIGH_BURST=40, EXTREME_BURST=116, HIGH_SCORE=7.0,
MEDIUM_SCORE=4.0), nothing re-derived or guessed there.

UPDATE (post parser-bug-fix, now the official final rule): mitigation_decision()
is applied TWICE per IP -- once against total_old (the frozen, original 0-15
scale model, for audit/comparison -- mitigation_decision_old) and once against
total_new (corrected 0-18.5 scale, backdoor/dropper signal included --
mitigation_decision_new). mitigation_decision_new now uses the empirically
re-derived FINAL_ACL_SCORE_THRESHOLD (8.5669, the P99.5 of total_new) combined
with a raw burst >= 10 condition as the ACL_BLOCK_CANDIDATE entry rule,
replacing the old HIGH_SCORE+temporal-category condition for that decision
specifically. All other tiers (REVIEW/MONITOR/BASE_SCORE_REVIEW/NO_ACTION)
are unchanged. mitigation_decision_new is the FINAL, official decision as of
this version -- not diagnostic-only anymore, per the agreed thesis methodology
(see threshold_analysis_new.py for the P99.5 derivation).

Inputs:
    scoring/post_auth_combined_final.csv   -- output of post_auth_scoring_final.py
    scoring/post_auth_temporal_features.csv -- unchanged burst features

Outputs:
    scoring/temporal_decision_final.csv
    scoring/temporal_decision_final_results.txt
"""

import csv
from collections import Counter

COMBINED = "scoring/post_auth_combined_final.csv"
TEMPORAL = "scoring/post_auth_temporal_features.csv"

OUTPUT = "scoring/temporal_decision_final.csv"
RESULTS = "scoring/temporal_decision_final_results.txt"


# ============================================================
# UNCHANGED constants from post_auth_temporal_decision_v2.py
# ============================================================

BURST_MIN = 10
HIGH_BURST = 40
EXTREME_BURST = 116

HIGH_SCORE = 7.0
MEDIUM_SCORE = 4.0

# ============================================================
# FINAL ACL BLOCKING RULE -- empirically derived P99.5 of the
# corrected total_new score distribution (parser bug fixed,
# backdoor/dropper signal included). Supersedes HIGH_SCORE as
# the entry condition specifically for ACL_BLOCK_CANDIDATE.
# See threshold_analysis_new.py for the derivation.
# ============================================================
FINAL_ACL_SCORE_THRESHOLD = 8.5669
FINAL_ACL_BURST_THRESHOLD = 10


def temporal_level(burst):
    """UNCHANGED from post_auth_temporal_decision_v2.py."""
    if burst < BURST_MIN:
        return "NORMAL"
    elif burst < HIGH_BURST:
        return "BURST"
    elif burst < EXTREME_BURST:
        return "HIGH_BURST"
    else:
        return "EXTREME_BURST"


def mitigation_decision(score, temporal, burst=None, use_final_acl_rule=False):
    """UNCHANGED from post_auth_temporal_decision_v2.py, EXCEPT:
    when use_final_acl_rule=True, the ACL_BLOCK_CANDIDATE entry condition
    is the empirically re-derived rule (score >= FINAL_ACL_SCORE_THRESHOLD
    AND burst >= FINAL_ACL_BURST_THRESHOLD) instead of the original
    HIGH_SCORE+temporal-category condition. All other tiers (REVIEW,
    MONITOR, BASE_SCORE_REVIEW, NO_ACTION) are untouched either way.

    mitigation_decision_old keeps use_final_acl_rule=False (the original,
    frozen model, for audit/comparison). mitigation_decision_new sets
    use_final_acl_rule=True -- this is now the FINAL, official rule, not
    just diagnostic, per the agreed thesis methodology.
    """
    if use_final_acl_rule:
        if score >= FINAL_ACL_SCORE_THRESHOLD and burst is not None and burst >= FINAL_ACL_BURST_THRESHOLD:
            return "ACL_BLOCK_CANDIDATE"
        if score >= HIGH_SCORE:
            return "BASE_SCORE_REVIEW"
        elif score >= MEDIUM_SCORE:
            if temporal == "EXTREME_BURST":
                return "HIGH_PRIORITY_REVIEW"
            elif temporal == "HIGH_BURST":
                return "REVIEW"
            elif temporal == "BURST":
                return "MONITOR"
            return "BASE_SCORE_REVIEW"
        else:
            if temporal == "EXTREME_BURST":
                return "HIGH_PRIORITY_REVIEW"
            elif temporal in ["BURST", "HIGH_BURST"]:
                return "MONITOR"
            return "NO_ACTION"

    if score >= HIGH_SCORE:
        if temporal in ["BURST", "HIGH_BURST", "EXTREME_BURST"]:
            return "ACL_BLOCK_CANDIDATE"
        return "BASE_SCORE_REVIEW"

    elif score >= MEDIUM_SCORE:
        if temporal == "EXTREME_BURST":
            return "HIGH_PRIORITY_REVIEW"
        elif temporal == "HIGH_BURST":
            return "REVIEW"
        elif temporal == "BURST":
            return "MONITOR"
        return "BASE_SCORE_REVIEW"

    else:
        if temporal == "EXTREME_BURST":
            return "HIGH_PRIORITY_REVIEW"
        elif temporal in ["BURST", "HIGH_BURST"]:
            return "MONITOR"
        return "NO_ACTION"


# ============================================================
# LOAD + JOIN
# ============================================================

combined = {}
with open(COMBINED, newline="", errors="ignore") as fh:
    for row in csv.DictReader(fh):
        ip = row["ip"]
        combined[ip] = {
            "commands": int(float(row["commands"])),
            "unique": int(float(row["unique"])),
            "severity_old": float(row["severity_old"]),
            "severity_new": float(row["severity_new"]),
            "intensity": float(row["intensity"]),
            "diversity": float(row["diversity"]),
            "total_old": float(row["total_old"]),
            "total_new": float(row["total_new"]),
            "risk_level_old": row["risk_level_old"],
            "risk_level_new": row["risk_level_new"],
            "persistence_backdoor_hits": int(row["persistence_backdoor_hits"]),
            "dropper_execution_hits": int(row["dropper_execution_hits"]),
        }

rows = []
with open(TEMPORAL, newline="", errors="ignore") as fh:
    for row in csv.DictReader(fh):
        ip = row["ip"]
        if ip not in combined:
            continue

        burst = int(float(row["burst_10plus_5s"]))
        temporal = temporal_level(burst)

        c = combined[ip]
        decision_old = mitigation_decision(c["total_old"], temporal)
        decision_new = mitigation_decision(c["total_new"], temporal, burst=burst, use_final_acl_rule=True)

        rows.append({
            "ip": ip,
            "commands": c["commands"],
            "unique": c["unique"],
            "severity_old": c["severity_old"],
            "severity_new": c["severity_new"],
            "intensity": c["intensity"],
            "diversity": c["diversity"],
            "total_old": c["total_old"],
            "total_new": c["total_new"],
            "risk_level_old": c["risk_level_old"],
            "risk_level_new": c["risk_level_new"],
            "persistence_backdoor_hits": c["persistence_backdoor_hits"],
            "dropper_execution_hits": c["dropper_execution_hits"],
            "successful_logins": int(float(row["successful_logins"])),
            "commands_per_login": float(row["commands_per_login"]),
            "activity_span_minutes": float(row["activity_span_minutes"]),
            "max_commands_5s": int(float(row["max_commands_5s"])),
            "max_commands_1min": int(float(row["max_commands_1min"])),
            "burst_10plus_5s": burst,
            "temporal_level": temporal,
            "mitigation_decision_old": decision_old,
            "mitigation_decision_new": decision_new,
        })

decision_priority = {
    "ACL_BLOCK_CANDIDATE": 5, "HIGH_PRIORITY_REVIEW": 4, "REVIEW": 3,
    "MONITOR": 2, "BASE_SCORE_REVIEW": 1, "NO_ACTION": 0,
}
rows.sort(
    key=lambda r: (
        decision_priority[r["mitigation_decision_old"]],
        r["burst_10plus_5s"],
        r["total_old"],
    ),
    reverse=True,
)


# ============================================================
# WRITE CSV
# ============================================================

if rows:
    fields = list(rows[0].keys())
    with open(OUTPUT, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# SUMMARY
# ============================================================

def summarize():
    lines = []
    lines.append("=" * 80)
    lines.append("TEMPORAL + MITIGATION DECISION -- FINAL")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"IPs analysed: {len(rows)}")
    lines.append("")

    old_counts = Counter(r["mitigation_decision_old"] for r in rows)
    new_counts = Counter(r["mitigation_decision_new"] for r in rows)

    lines.append("DECISION DISTRIBUTION -- validated (old) vs diagnostic (new)")
    lines.append("-" * 80)
    for d in ["ACL_BLOCK_CANDIDATE", "HIGH_PRIORITY_REVIEW", "REVIEW", "MONITOR", "BASE_SCORE_REVIEW", "NO_ACTION"]:
        lines.append(f"{d:25s}: old={old_counts[d]:5d}   new={new_counts[d]:5d}")
    lines.append("")

    moved = [r for r in rows if r["mitigation_decision_old"] != r["mitigation_decision_new"]]
    lines.append(f"IPs whose decision CHANGED under the patch: {len(moved)}")
    lines.append("-" * 80)
    for r in sorted(moved, key=lambda r: r["total_new"], reverse=True)[:30]:
        lines.append(
            f"{r['ip']:18s} {r['mitigation_decision_old']:20s} -> {r['mitigation_decision_new']:20s}  "
            f"(backdoor={r['persistence_backdoor_hits']}, dropper={r['dropper_execution_hits']}, "
            f"temporal={r['temporal_level']}, total {r['total_old']:.2f}->{r['total_new']:.2f})"
        )
    lines.append("")

    newly_block = [
        r for r in rows
        if r["mitigation_decision_new"] == "ACL_BLOCK_CANDIDATE"
        and r["mitigation_decision_old"] != "ACL_BLOCK_CANDIDATE"
    ]
    lines.append(f"IPs newly qualifying as ACL_BLOCK_CANDIDATE under the final P99.5 rule: {len(newly_block)}")
    lines.append(f"(Final rule now OFFICIAL: total_new >= {FINAL_ACL_SCORE_THRESHOLD} AND burst >= {FINAL_ACL_BURST_THRESHOLD})")
    lines.append("-" * 80)
    for r in sorted(newly_block, key=lambda r: r["total_new"], reverse=True):
        lines.append(
            f"{r['ip']:18s} old_decision={r['mitigation_decision_old']:20s} "
            f"backdoor_hits={r['persistence_backdoor_hits']}  dropper_hits={r['dropper_execution_hits']}  "
            f"total_old={r['total_old']:.2f}  total_new={r['total_new']:.2f}  temporal={r['temporal_level']}"
        )
    lines.append("")

    return "\n".join(lines)


summary_text = summarize()
print(summary_text)

with open(RESULTS, "w") as f:
    f.write(summary_text + "\n")

print(f"Created: {OUTPUT}")
print(f"Created: {RESULTS}")
