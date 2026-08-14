import csv
import math
from collections import defaultdict, Counter

F = "research_csv/all_logs_full.csv"

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


# ---------------------------------------------------------
# Collect category event counts and unique commands
# ---------------------------------------------------------

ip_counts = defaultdict(Counter)
ip_unique = defaultdict(lambda: defaultdict(set))

with open(F, newline="", errors="ignore") as fh:

    for row in csv.DictReader(fh):

        ip = (row.get("src_ip") or "").strip()
        command = (row.get("command") or "").strip()

        if not ip or not command:
            continue

        category = get_category(command)

        if category:
            ip_counts[ip][category] += 1
            ip_unique[ip][category].add(command)


# ---------------------------------------------------------
# V3 category score
#
# 50% BASE:
#     category detected
#
# 50% REPETITION:
#     gradually increases with event count
#
# Saturation:
#     50 events -> near maximum
# ---------------------------------------------------------

def category_score(count, maximum):

    if count <= 0:
        return 0.0

    base = maximum * 0.50

    # Repetition factor:
    # 1 event  -> 0
    # 10       -> moderate
    # 50+      -> maximum
    repetition = math.log1p(count) / math.log1p(50)

    repetition = min(repetition, 1.0)

    bonus = maximum * 0.50 * repetition

    return base + bonus


results = []

for ip, counts in ip_counts.items():

    total = 0.0
    details = []

    for category, maximum in WEIGHTS.items():

        count = counts.get(category, 0)

        if count == 0:
            continue

        unique_count = len(
            ip_unique[ip][category]
        )

        score = category_score(
            count,
            maximum
        )

        total += score

        details.append(
            (
                category,
                count,
                unique_count,
                score
            )
        )

    results.append(
        (
            ip,
            min(total, 7.0),
            details
        )
    )


# ---------------------------------------------------------
# Statistics
# ---------------------------------------------------------

values = sorted(x[1] for x in results)


def percentile(values, p):

    if not values:
        return 0

    i = (len(values) - 1) * p / 100

    lo = int(i)
    hi = min(lo + 1, len(values) - 1)

    if lo == hi:
        return values[lo]

    return values[lo] + (
        values[hi] - values[lo]
    ) * (i - lo)


print("=" * 70)
print("POST-AUTHENTICATION BEHAVIOUR SEVERITY V3")
print("=" * 70)

print()
print("IPs with classified behaviour:", len(values))

print()
print("P50 :", round(percentile(values, 50), 2))
print("P75 :", round(percentile(values, 75), 2))
print("P90 :", round(percentile(values, 90), 2))
print("P95 :", round(percentile(values, 95), 2))
print("P99 :", round(percentile(values, 99), 2))
print("MAX :", round(max(values), 2))
print("MEAN:", round(sum(values) / len(values), 2))

print()

for threshold in [1, 2, 3, 4, 5, 6, 7]:

    count = sum(
        v >= threshold
        for v in values
    )

    print(
        f">= {threshold} points : {count}"
    )


# ---------------------------------------------------------
# Known IPs
# ---------------------------------------------------------

TARGETS = [
    "35.229.125.98",
    "34.75.237.227",
    "34.139.191.163",
    "136.107.187.197",
    "34.150.142.107",
    "34.138.181.9",
    "103.116.107.209",
    "200.89.69.247",
    "213.209.159.158",
]

lookup = {
    ip: (score, details)
    for ip, score, details in results
}

print()
print("=" * 70)
print("KNOWN HIGH-ACTIVITY IPs")
print("=" * 70)

for ip in TARGETS:

    if ip not in lookup:
        continue

    score, details = lookup[ip]

    print()
    print(f"{ip:18} SCORE={score:5.2f}/7")

    for category, count, unique_count, score_value in details:

        print(
            f"  {category:25} "
            f"events={count:4} "
            f"unique={unique_count:2} "
            f"score={score_value:4.2f}"
        )


# ---------------------------------------------------------
# Top 30
# ---------------------------------------------------------

print()
print("=" * 70)
print("TOP 30 IPs BY V3 BEHAVIOUR SEVERITY")
print("=" * 70)

for ip, score, details in sorted(
    results,
    key=lambda x: -x[1]
)[:30]:

    categories = ",".join(
        d[0] for d in details
    )

    print(
        f"{ip:18} "
        f"score={score:5.2f}/7 "
        f"categories={categories}"
    )


# ---------------------------------------------------------
# Reference values
# ---------------------------------------------------------

print()
print("=" * 70)
print("REFERENCE CATEGORY SCORES")
print("=" * 70)

for value in [1, 2, 5, 10, 20, 50, 100, 500, 1000]:

    score = category_score(
        value,
        1.0
    )

    print(
        f"{value:5} events -> "
        f"{score:.3f} / 1.0"
    )
