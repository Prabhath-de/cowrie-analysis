import csv
import math

INPUT = "scoring/post_auth_combined_v1.csv"
OUTPUT = "scoring/post_auth_combined_v2.csv"

# ============================================================
# DATA-DRIVEN BOUNDARIES
# ============================================================

# Severity V3
SEVERITY_MAX = 7.0

# Intensity V3
P50 = 2
P75 = 8
P90 = 28
P95 = 55.75
P99 = 761
MAX_COMMANDS = 13431

# Diversity V3
D_P95 = 3
D_P99 = 14
D_MAX = 17


# ============================================================
# INTENSITY V3
# ============================================================

def intensity_score(x):
    x = max(0.0, x)

    if x <= P50:
        return 0.5 * (x / P50)

    elif x <= P75:
        return 0.5 + (
            0.5 *
            (math.log1p(x / P50) /
             math.log1p(P75 / P50))
        )

    elif x <= P90:
        return 1.0 + (
            0.5 *
            (math.log1p(x / P75) /
             math.log1p(P90 / P75))
        )

    elif x <= P95:
        return 1.5 + (
            1.0 *
            (math.log1p(x / P90) /
             math.log1p(P95 / P90))
        ) - 1.0

    elif x <= P99:
        return 2.5 + (
            1.0 *
            (math.log1p(x / P95) /
             math.log1p(P99 / P95))
        ) - 1.0

    else:
        if MAX_COMMANDS <= P99:
            return 5.0

        return min(
            5.0,
            4.0 + (
                math.log1p(x / P99) /
                math.log1p(MAX_COMMANDS / P99)
            )
        )


# ============================================================
# DIVERSITY V3
# ============================================================

def diversity_score(x):
    x = max(0, x)

    if x <= 1:
        return 0.0

    if x >= D_MAX:
        return 3.0

    points = [
        (1, 0.0),
        (D_P95, 1.0),
        (D_P99, 2.0),
        (D_MAX, 3.0),
    ]

    for i in range(1, len(points)):
        x0, y0 = points[i - 1]
        x1, y1 = points[i]

        if x <= x1:
            ratio = (
                math.log1p(x) - math.log1p(x0)
            ) / (
                math.log1p(x1) - math.log1p(x0)
            )

            return y0 + ratio * (y1 - y0)

    return 3.0


# ============================================================
# RISK LEVEL
# ============================================================

def risk_level(score):
    if score >= 10:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


# ============================================================
# LOAD + RECALCULATE
# ============================================================

rows = []

with open(INPUT, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        commands = int(float(row["commands"]))
        unique = int(float(row["unique"]))

        # Severity from V1 is retained here because
        # the current validated Severity V3 value is already
        # represented in the source scoring pipeline.
        severity = float(row["severity"])

        intensity = intensity_score(commands)
        diversity = diversity_score(unique)

        total = severity + intensity + diversity

        new_row = {
            "ip": row["ip"],
            "commands": commands,
            "unique": unique,
            "severity": severity,
            "intensity": intensity,
            "diversity": diversity,
            "total": total,
            "risk_level": risk_level(total),
        }

        rows.append(new_row)


# ============================================================
# SORT
# ============================================================

rows.sort(key=lambda r: r["total"], reverse=True)


# ============================================================
# WRITE
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
]

with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()

    for row in rows:
        writer.writerow({
            "ip": row["ip"],
            "commands": row["commands"],
            "unique": row["unique"],
            "severity": f"{row['severity']:.4f}",
            "intensity": f"{row['intensity']:.4f}",
            "diversity": f"{row['diversity']:.4f}",
            "total": f"{row['total']:.4f}",
            "risk_level": row["risk_level"],
        })


# ============================================================
# SUMMARY
# ============================================================

from collections import Counter

levels = Counter(r["risk_level"] for r in rows)

print("=" * 70)
print("POST-AUTH COMBINED V2")
print("=" * 70)

print("IPs analysed :", len(rows))
print("Maximum score: 15")
print()

print("RISK DISTRIBUTION")
print("-" * 40)

for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    print(f"{level:10s}: {levels[level]:5d}")

print()
print("TOP 30")
print("-" * 70)

for r in rows[:30]:
    print(
        f"{r['ip']:18s} "
        f"commands={r['commands']:6d} "
        f"unique={r['unique']:2d} "
        f"severity={r['severity']:.2f}/7 "
        f"intensity={r['intensity']:.2f}/5 "
        f"diversity={r['diversity']:.2f}/3 "
        f"TOTAL={r['total']:.2f}/15 "
        f"{r['risk_level']}"
    )

print()
print("Created:", OUTPUT)
