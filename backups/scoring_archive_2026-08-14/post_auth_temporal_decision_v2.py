import csv
from collections import Counter

INPUT = "scoring/post_auth_temporal_crosscheck_v1.csv"

OUTPUT = "scoring/post_auth_temporal_decision_v2.csv"
RESULTS = "scoring/post_auth_temporal_decision_v2_results.txt"


# ============================================================
# DATA-DRIVEN TEMPORAL BOUNDARIES
# ============================================================

BURST_MIN = 10
HIGH_BURST = 40
EXTREME_BURST = 116

HIGH_SCORE = 7.0
MEDIUM_SCORE = 4.0


# ============================================================
# TEMPORAL CLASSIFICATION
# ============================================================

def temporal_level(burst):

    if burst < BURST_MIN:
        return "NORMAL"

    elif burst < HIGH_BURST:
        return "BURST"

    elif burst < EXTREME_BURST:
        return "HIGH_BURST"

    else:
        return "EXTREME_BURST"


# ============================================================
# MITIGATION DECISION
# ============================================================

def mitigation_decision(score, temporal):

    # --------------------------------------------------------
    # HIGH BASE THREAT
    # --------------------------------------------------------

    if score >= HIGH_SCORE:

        if temporal in [
            "BURST",
            "HIGH_BURST",
            "EXTREME_BURST"
        ]:
            return "ACL_BLOCK_CANDIDATE"

        return "BASE_SCORE_REVIEW"


    # --------------------------------------------------------
    # MEDIUM BASE THREAT
    # --------------------------------------------------------

    elif score >= MEDIUM_SCORE:

        if temporal == "EXTREME_BURST":
            return "HIGH_PRIORITY_REVIEW"

        elif temporal == "HIGH_BURST":
            return "REVIEW"

        elif temporal == "BURST":
            return "MONITOR"

        return "BASE_SCORE_REVIEW"


    # --------------------------------------------------------
    # LOW BASE THREAT
    # --------------------------------------------------------

    else:

        if temporal == "EXTREME_BURST":
            return "HIGH_PRIORITY_REVIEW"

        elif temporal in [
            "BURST",
            "HIGH_BURST"
        ]:
            return "MONITOR"

        return "NO_ACTION"


# ============================================================
# LOAD
# ============================================================

rows = []

with open(INPUT, newline="", errors="ignore") as fh:

    reader = csv.DictReader(fh)

    for row in reader:

        score = float(row["total"])
        burst = int(float(row["burst_10plus_5s"]))

        temporal = temporal_level(burst)

        decision = mitigation_decision(
            score,
            temporal
        )

        new_row = dict(row)

        new_row["temporal_level_v2"] = temporal
        new_row["mitigation_decision_v2"] = decision

        rows.append(new_row)


# ============================================================
# SORT
# ============================================================

decision_priority = {
    "ACL_BLOCK_CANDIDATE": 5,
    "HIGH_PRIORITY_REVIEW": 4,
    "REVIEW": 3,
    "MONITOR": 2,
    "BASE_SCORE_REVIEW": 1,
    "NO_ACTION": 0,
}

rows.sort(
    key=lambda r: (
        decision_priority[
            r["mitigation_decision_v2"]
        ],
        float(r["burst_10plus_5s"]),
        float(r["total"])
    ),
    reverse=True
)


# ============================================================
# WRITE CSV
# ============================================================

fields = list(rows[0].keys())

with open(OUTPUT, "w", newline="") as fh:

    writer = csv.DictWriter(
        fh,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(rows)


# ============================================================
# STATISTICS
# ============================================================

temporal_counts = Counter(
    r["temporal_level_v2"]
    for r in rows
)

decision_counts = Counter(
    r["mitigation_decision_v2"]
    for r in rows
)


# ============================================================
# RESULTS
# ============================================================

with open(RESULTS, "w") as out:

    out.write("=" * 80 + "\n")
    out.write("POST-AUTH TEMPORAL DECISION V2\n")
    out.write("=" * 80 + "\n\n")

    out.write("TEMPORAL BOUNDARIES\n")
    out.write("-" * 50 + "\n")
    out.write(f"Burst minimum : {BURST_MIN}\n")
    out.write(f"High burst    : {HIGH_BURST}\n")
    out.write(f"Extreme burst : {EXTREME_BURST}\n\n")

    out.write("TEMPORAL DISTRIBUTION\n")
    out.write("-" * 50 + "\n")

    for level in [
        "NORMAL",
        "BURST",
        "HIGH_BURST",
        "EXTREME_BURST"
    ]:

        count = temporal_counts[level]

        pct = count / len(rows) * 100

        out.write(
            f"{level:18s}: "
            f"{count:5d} "
            f"({pct:6.2f}%)\n"
        )

    out.write("\n")
    out.write("MITIGATION DECISIONS\n")
    out.write("-" * 50 + "\n")

    for decision in [
        "ACL_BLOCK_CANDIDATE",
        "HIGH_PRIORITY_REVIEW",
        "REVIEW",
        "MONITOR",
        "BASE_SCORE_REVIEW",
        "NO_ACTION"
    ]:

        count = decision_counts[decision]

        pct = count / len(rows) * 100

        out.write(
            f"{decision:25s}: "
            f"{count:5d} "
            f"({pct:6.2f}%)\n"
        )

    out.write("\n")
    out.write("=" * 80 + "\n")
    out.write("ACL BLOCK CANDIDATES\n")
    out.write("=" * 80 + "\n\n")

    for r in rows:

        if r["mitigation_decision_v2"] != \
                "ACL_BLOCK_CANDIDATE":
            continue

        out.write(
            f"{r['ip']:18s} "
            f"score={float(r['total']):5.2f}/15 "
            f"burst={int(float(r['burst_10plus_5s'])):5d} "
            f"max5s={int(float(r['max_commands_5s'])):3d} "
            f"max1m={int(float(r['max_commands_1min'])):3d} "
            f"temporal={r['temporal_level_v2']:13s}\n"
        )

    out.write("\n")
    out.write("=" * 80 + "\n")
    out.write("HIGH PRIORITY REVIEW\n")
    out.write("=" * 80 + "\n\n")

    for r in rows:

        if r["mitigation_decision_v2"] != \
                "HIGH_PRIORITY_REVIEW":
            continue

        out.write(
            f"{r['ip']:18s} "
            f"score={float(r['total']):5.2f}/15 "
            f"burst={int(float(r['burst_10plus_5s'])):5d} "
            f"max5s={int(float(r['max_commands_5s'])):3d} "
            f"max1m={int(float(r['max_commands_1min'])):3d} "
            f"temporal={r['temporal_level_v2']:13s}\n"
        )


# ============================================================
# TERMINAL OUTPUT
# ============================================================

print("=" * 80)
print("POST-AUTH TEMPORAL DECISION V2")
print("=" * 80)

print()
print("TEMPORAL DISTRIBUTION")

for level in [
    "NORMAL",
    "BURST",
    "HIGH_BURST",
    "EXTREME_BURST"
]:

    print(
        f"{level:18s}: "
        f"{temporal_counts[level]:5d}"
    )

print()
print("MITIGATION DECISIONS")

for decision in [
    "ACL_BLOCK_CANDIDATE",
    "HIGH_PRIORITY_REVIEW",
    "REVIEW",
    "MONITOR",
    "BASE_SCORE_REVIEW",
    "NO_ACTION"
]:

    print(
        f"{decision:25s}: "
        f"{decision_counts[decision]:5d}"
    )

print()
print("ACL BLOCK CANDIDATES")
print("-" * 80)

for r in rows:

    if r["mitigation_decision_v2"] == \
            "ACL_BLOCK_CANDIDATE":

        print(
            f"{r['ip']:18s} "
            f"score={float(r['total']):5.2f}/15 "
            f"burst={int(float(r['burst_10plus_5s'])):5d} "
            f"temporal={r['temporal_level_v2']}"
        )

print()
print("Created:", OUTPUT)
print("Created:", RESULTS)
