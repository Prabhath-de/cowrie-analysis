import csv
from collections import Counter

TEMPORAL = "scoring/post_auth_temporal_features.csv"
COMBINED = "scoring/post_auth_combined_v3.csv"

OUTPUT = "scoring/post_auth_temporal_crosscheck_v1.csv"
RESULTS = "scoring/post_auth_temporal_crosscheck_v1_results.txt"


# ============================================================
# LOAD V3 SCORES
# ============================================================

v3 = {}

with open(COMBINED, newline="", errors="ignore") as fh:
    for row in csv.DictReader(fh):

        ip = row["ip"]

        v3[ip] = {
            "commands": int(float(row["commands"])),
            "unique": int(float(row["unique"])),
            "severity": float(row["severity"]),
            "intensity": float(row["intensity"]),
            "diversity": float(row["diversity"]),
            "total": float(row["total"]),
            "risk_level": row["risk_level"],
        }


# ============================================================
# LOAD TEMPORAL FEATURES
# ============================================================

rows = []

with open(TEMPORAL, newline="", errors="ignore") as fh:

    for row in csv.DictReader(fh):

        ip = row["ip"]

        if ip not in v3:
            continue

        max_5s = int(float(row["max_commands_5s"]))
        max_1min = int(float(row["max_commands_1min"]))
        burst = int(float(row["burst_10plus_5s"]))

        # ----------------------------------------------------
        # TEMPORAL CLASSIFICATION
        # ----------------------------------------------------

        if burst > 0:
            temporal_level = "BURST"

        elif max_5s >= 10:
            temporal_level = "HIGH_FREQUENCY"

        elif max_5s >= 3 or max_1min >= 10:
            temporal_level = "ELEVATED"

        else:
            temporal_level = "NORMAL"

        # ----------------------------------------------------
        # ACL DECISION MODIFIER
        # ----------------------------------------------------

        base_total = v3[ip]["total"]

        if temporal_level == "BURST":
            decision = "IMMEDIATE_REVIEW"

        elif temporal_level == "HIGH_FREQUENCY":
            decision = "REVIEW"

        elif temporal_level == "ELEVATED":
            decision = "MONITOR"

        else:
            decision = "BASE_SCORE_ONLY"

        rows.append({
            "ip": ip,
            "commands": v3[ip]["commands"],
            "unique": v3[ip]["unique"],
            "severity": v3[ip]["severity"],
            "intensity": v3[ip]["intensity"],
            "diversity": v3[ip]["diversity"],
            "total": base_total,
            "risk_level": v3[ip]["risk_level"],
            "successful_logins": int(float(row["successful_logins"])),
            "commands_per_login": float(row["commands_per_login"]),
            "activity_span_minutes": float(row["activity_span_minutes"]),
            "max_commands_5s": max_5s,
            "max_commands_1min": max_1min,
            "burst_10plus_5s": burst,
            "temporal_level": temporal_level,
            "decision": decision,
        })


# ============================================================
# SORT
# ============================================================

rows.sort(
    key=lambda x: (
        x["burst_10plus_5s"],
        x["max_commands_5s"],
        x["total"]
    ),
    reverse=True
)


# ============================================================
# SAVE CSV
# ============================================================

fields = [
    "ip",
    "commands",
    "unique",
    "severity",
    "intensity",
    "diversity",
    "total",
    "risk_level",
    "successful_logins",
    "commands_per_login",
    "activity_span_minutes",
    "max_commands_5s",
    "max_commands_1min",
    "burst_10plus_5s",
    "temporal_level",
    "decision",
]

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
    r["temporal_level"]
    for r in rows
)

decision_counts = Counter(
    r["decision"]
    for r in rows
)

burst_ips = [
    r for r in rows
    if r["burst_10plus_5s"] > 0
]


# ============================================================
# RESULTS
# ============================================================

with open(RESULTS, "w") as out:

    out.write("=" * 80 + "\n")
    out.write("POST-AUTH TEMPORAL BURST + V3 CROSS-CHECK\n")
    out.write("=" * 80 + "\n\n")

    out.write(
        f"IPs analysed : {len(rows)}\n"
    )

    out.write(
        f"Burst IPs    : {len(burst_ips)}\n\n"
    )

    out.write("TEMPORAL CLASSIFICATION\n")
    out.write("-" * 50 + "\n")

    for level in [
        "NORMAL",
        "ELEVATED",
        "HIGH_FREQUENCY",
        "BURST"
    ]:

        count = temporal_counts[level]

        pct = (
            count / len(rows) * 100
            if rows else 0
        )

        out.write(
            f"{level:16s}: "
            f"{count:5d} "
            f"({pct:6.2f}%)\n"
        )

    out.write("\n")
    out.write("ACL DECISION MODIFIER\n")
    out.write("-" * 50 + "\n")

    for decision in [
        "BASE_SCORE_ONLY",
        "MONITOR",
        "REVIEW",
        "IMMEDIATE_REVIEW"
    ]:

        count = decision_counts[decision]

        pct = (
            count / len(rows) * 100
            if rows else 0
        )

        out.write(
            f"{decision:20s}: "
            f"{count:5d} "
            f"({pct:6.2f}%)\n"
        )

    out.write("\n")
    out.write("=" * 80 + "\n")
    out.write("BURST IPs\n")
    out.write("=" * 80 + "\n\n")

    for r in burst_ips:

        out.write(
            f"{r['ip']:18s} "
            f"commands={r['commands']:5d} "
            f"unique={r['unique']:2d} "
            f"logins={r['successful_logins']:4d} "
            f"score={r['total']:5.2f}/15 "
            f"risk={r['risk_level']:8s} "
            f"max5s={r['max_commands_5s']:3d} "
            f"max1m={r['max_commands_1min']:3d} "
            f"burst={r['burst_10plus_5s']:5d} "
            f"decision={r['decision']}\n"
        )

    out.write("\n")
    out.write("=" * 80 + "\n")
    out.write("TOP BURST IPs BY TEMPORAL ACTIVITY\n")
    out.write("=" * 80 + "\n\n")

    for r in rows[:30]:

        out.write(
            f"{r['ip']:18s} "
            f"burst={r['burst_10plus_5s']:5d} "
            f"max5s={r['max_commands_5s']:3d} "
            f"max1m={r['max_commands_1min']:3d} "
            f"score={r['total']:5.2f}/15 "
            f"{r['risk_level']:8s} "
            f"{r['decision']}\n"
        )


# ============================================================
# TERMINAL OUTPUT
# ============================================================

print("=" * 80)
print("POST-AUTH TEMPORAL BURST + V3 CROSS-CHECK")
print("=" * 80)

print()
print("IPs analysed:", len(rows))
print()

print("TEMPORAL CLASSIFICATION")
print("-" * 50)

for level in [
    "NORMAL",
    "ELEVATED",
    "HIGH_FREQUENCY",
    "BURST"
]:

    count = temporal_counts[level]

    print(
        f"{level:16s}: {count:5d}"
    )

print()
print("ACL DECISION MODIFIER")
print("-" * 50)

for decision in [
    "BASE_SCORE_ONLY",
    "MONITOR",
    "REVIEW",
    "IMMEDIATE_REVIEW"
]:

    print(
        f"{decision:20s}: "
        f"{decision_counts[decision]:5d}"
    )

print()
print("BURST IPs:", len(burst_ips))

print()
print("TOP BURST IPs")
print("-" * 80)

for r in burst_ips[:20]:

    print(
        f"{r['ip']:18s} "
        f"score={r['total']:5.2f}/15 "
        f"risk={r['risk_level']:8s} "
        f"max5s={r['max_commands_5s']:3d} "
        f"max1m={r['max_commands_1min']:3d} "
        f"burst={r['burst_10plus_5s']:5d} "
        f"{r['decision']}"
    )

print()
print("Created:", OUTPUT)
print("Created:", RESULTS)
