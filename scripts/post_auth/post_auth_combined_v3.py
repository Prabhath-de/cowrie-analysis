import csv
import math
from collections import Counter

INPUT = "scoring/post_auth_combined_v1.csv"
OUTPUT = "scoring/post_auth_combined_v3.csv"

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
# SEVERITY V3
# ============================================================

WEIGHTS = {
    "basic_recon": 0.5,
    "system_recon": 0.5,
    "file_modification": 1.0,
    "download_transfer": 1.0,
    "persistence": 1.5,
    "account_privilege": 1.5,
    "remote_access_execution": 1.0,
}

COMMANDS = {
    "basic_recon": {
        "uname", "hostname", "pwd", "whoami", "id",
        "ls", "env", "history", "uptime", "which"
    },
    "system_recon": {
        "ps", "top", "df", "free", "lscpu", "lspci",
        "ifconfig", "ip", "netstat", "ss", "mount",
        "nproc", "ulimit", "locate"
    },
    "file_modification": {
        "rm", "chmod", "touch"
    },
    "download_transfer": {
        "wget", "curl", "scp"
    },
    "persistence": {
        "crontab", "systemctl", "nohup"
    },
    "account_privilege": {
        "useradd", "usermod", "sudo"
    },
    "remote_access_execution": {
        "ssh", "sh", "nc"
    },
}


def get_category(command):
    command = (command or "").strip()

    if not command:
        return None

    token = command.split()[0]
    token = token.split("/")[-1]

    for category, commands in COMMANDS.items():
        if token in commands:
            return category

    return None


def category_score(count, maximum):
    if count <= 0:
        return 0.0

    base = maximum * 0.50

    repetition = (
        math.log1p(count) /
        math.log1p(50)
    )

    repetition = min(repetition, 1.0)

    bonus = maximum * 0.50 * repetition

    return base + bonus


def calculate_severity(ip, command_data):
    counts = Counter()

    for command in command_data:
        category = get_category(command)

        if category:
            counts[category] += 1

    total = 0.0

    for category, maximum in WEIGHTS.items():
        total += category_score(
            counts.get(category, 0),
            maximum
        )

    return min(total, SEVERITY_MAX)


# ============================================================
# INTENSITY V3
# ============================================================

def intensity_score(x):
    x = max(0.0, float(x))

    if x <= P50:
        return 0.5 * (x / P50)

    elif x <= P75:
        ratio = (
            math.log1p(x / P50) -
            math.log1p(P50 / P50)
        ) / (
            math.log1p(P75 / P50) -
            math.log1p(P50 / P50)
        )

        return 0.5 + 0.5 * ratio

    elif x <= P90:
        ratio = (
            math.log1p(x / P75) -
            math.log1p(P75 / P75)
        ) / (
            math.log1p(P90 / P75) -
            math.log1p(P75 / P75)
        )

        return 1.0 + 0.5 * ratio

    elif x <= P95:
        ratio = (
            math.log1p(x / P90) -
            math.log1p(P90 / P90)
        ) / (
            math.log1p(P95 / P90) -
            math.log1p(P90 / P90)
        )

        return 1.5 + 1.0 * ratio

    elif x <= P99:
        ratio = (
            math.log1p(x / P95) -
            math.log1p(P95 / P95)
        ) / (
            math.log1p(P99 / P95) -
            math.log1p(P95 / P95)
        )

        return 2.5 + 1.0 * ratio

    else:
        if MAX_COMMANDS <= P99:
            return 5.0

        ratio = (
            math.log1p((x - P99) / P99)
        ) / (
            math.log1p(
                (MAX_COMMANDS - P99) / P99
            )
        )

        return min(
            5.0,
            3.5 + 1.5 * ratio
        )


# ============================================================
# DIVERSITY V3
# ============================================================

def diversity_score(x):
    x = max(0, int(x))

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
# LOAD COMMAND DATA
# ============================================================

# post_auth_combined_v1 already contains the required
# IP-level command and unique-command information.
#
# Severity is recalculated from the original command log
# so that V3 does not inherit the V1 severity value.

F = "research_csv/all_logs_full.csv"

ip_commands = {}

with open(F, newline="", errors="ignore") as fh:
    reader = csv.DictReader(fh)

    for row in reader:
        ip = (row.get("src_ip") or "").strip()
        command = (row.get("command") or "").strip()

        if not ip or not command:
            continue

        ip_commands.setdefault(ip, []).append(command)


# ============================================================
# LOAD FEATURES
# ============================================================

rows = []

with open(INPUT, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        ip = row["ip"]

        commands = int(float(row["commands"]))
        unique = int(float(row["unique"]))

        severity = calculate_severity(
            ip,
            ip_commands.get(ip, [])
        )

        intensity = intensity_score(commands)

        diversity = diversity_score(unique)

        total = severity + intensity + diversity

        rows.append({
            "ip": ip,
            "commands": commands,
            "unique": unique,
            "severity": severity,
            "intensity": intensity,
            "diversity": diversity,
            "total": total,
            "risk_level": risk_level(total),
        })


# ============================================================
# SORT
# ============================================================

rows.sort(
    key=lambda r: r["total"],
    reverse=True
)


# ============================================================
# WRITE CSV
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
    writer = csv.DictWriter(
        f,
        fieldnames=fields
    )

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

levels = Counter(
    r["risk_level"]
    for r in rows
)

print("=" * 70)
print("POST-AUTH COMBINED V3")
print("=" * 70)

print()
print("IPs analysed :", len(rows))
print("Maximum score: 15")

print()
print("RISK DISTRIBUTION")
print("-" * 40)

for level in [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]:
    print(
        f"{level:10s}: {levels[level]:5d}"
    )

print()
print("TOP 30")
print("-" * 90)

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
