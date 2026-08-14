"""
post_auth_scoring_final.py

FINALIZED post-authentication severity/intensity/diversity scorer.

This consolidates post_auth_combined_v3.py (your current live version) --
same intensity_score() curve, same diversity_score() curve, same
category_score() formula, same calibration constants (P50/P75/P90/P95/P99,
D_P95/D_P99/D_MAX) -- UNCHANGED. Nothing about the existing calibration is
re-derived or guessed.

The one addition: two new severity categories, detected via full-string
regex scan rather than get_category()'s first-token check, which confirmed
misses both patterns below when they appear inside a single chained/compound
command (your own node01 data shows this is exactly how they occur):

  - persistence_backdoor: authorized_keys injection / .ssh chattr tampering
      e.g. "cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa ...' >>
            .ssh/authorized_keys && chmod -R go= ~/.ssh"
      -- first token "cd", invisible to get_category(); 29 raw hits in
         your command-frequency dump (15 chattr + 14 key-injection).

  - dropper_execution: fetch piped straight to a shell, or fetch + chmod/exec
    later in the same line
      e.g. the scp-with-wget/curl-fallback payload -- first token "echo",
      also invisible to get_category().

Both are reported ADDITIVELY and SEPARATELY from the old severity score so
you can see exactly which IPs move and by how much -- nothing is silently
overwritten. risk_level() thresholds are print-flagged, not auto-rescaled,
since they were calibrated on the old 0-15 scale (see NOTE in main()).

Inputs (unchanged from your existing pipeline):
    scoring/post_auth_combined_v1.csv   -- per-IP commands/unique counts
    research_csv/all_logs_full.csv      -- per-event log (src_ip, command)

Outputs:
    scoring/post_auth_combined_final.csv
    scoring/post_auth_combined_final_results.txt
"""

import csv
import math
from collections import Counter

from detect_advanced_patterns import (
    has_ssh_backdoor_pattern,
    has_dropper_oneliner_pattern,
    has_staged_dropper_pattern,
    has_staged_ssh_backdoor_pattern,
)

INPUT = "scoring/post_auth_combined_v1.csv"
LOGFILE = "research_csv/all_logs_full.csv"
OUTPUT = "scoring/post_auth_combined_final.csv"
RESULTS = "scoring/post_auth_combined_final_results.txt"


# ============================================================
# SEVERITY -- unchanged constants from post_auth_combined_v3.py
# ============================================================

SEVERITY_MAX_OLD = 7.0  # unchanged -- exact sum of the 7 original weights

WEIGHTS = {
    "basic_recon": 0.5,
    "system_recon": 0.5,
    "file_modification": 1.0,
    "download_transfer": 1.0,
    "persistence": 1.5,
    "account_privilege": 1.5,
    "remote_access_execution": 1.0,
}

# NEW categories -- detected via full-string scan, not the tokenized dict
# below. Weighted above account_privilege (1.5) since these represent
# confirmed follow-through (a working backdoor / a fetch-and-run), not
# just an attempted privileged command.
NEW_WEIGHTS = {
    "persistence_backdoor": 2.0,
    "dropper_execution": 1.5,
}

SEVERITY_MAX_NEW = SEVERITY_MAX_OLD + sum(NEW_WEIGHTS.values())  # 7.0 + 3.5 = 10.5

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
    """UNCHANGED from post_auth_combined_v3.py -- first-token classification
    for the 7 original categories. Left exactly as-is."""
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
    """UNCHANGED from post_auth_combined_v3.py."""
    if count <= 0:
        return 0.0
    base = maximum * 0.50
    repetition = min(math.log1p(count) / math.log1p(50), 1.0)
    bonus = maximum * 0.50 * repetition
    return base + bonus


def calculate_severity(command_data):
    """Returns (old_severity, new_severity, category_counts) for one IP's
    full list of raw command strings.

    old_severity: exactly what post_auth_combined_v3.py would have produced
    new_severity: old_severity's categories PLUS the two new full-string
                  scanned categories, capped at SEVERITY_MAX_NEW instead
                  of SEVERITY_MAX_OLD
    """
    counts = Counter()
    for command in command_data:
        category = get_category(command)
        if category:
            counts[category] += 1
        # Full-string, single-command scans -- independent of get_category().
        if has_ssh_backdoor_pattern(command):
            counts["persistence_backdoor"] += 1
        if has_dropper_oneliner_pattern(command):
            counts["dropper_execution"] += 1

    # IP-level aggregate scans -- catches the same two patterns when they're
    # split across separate command.input events rather than one chained
    # string (all_logs_full.csv has no session column to scope this tighter;
    # confirmed necessary by testing against the staged wget->chmod->./exec
    # example, which has_dropper_oneliner_pattern alone does not catch).
    # Counted once per IP, on top of any per-command hits above.
    if has_staged_dropper_pattern(command_data):
        counts["dropper_execution"] += 1
    if has_staged_ssh_backdoor_pattern(command_data):
        counts["persistence_backdoor"] += 1

    old_total = 0.0
    for category, maximum in WEIGHTS.items():
        old_total += category_score(counts.get(category, 0), maximum)
    old_total = min(old_total, SEVERITY_MAX_OLD)

    new_total = old_total
    for category, maximum in NEW_WEIGHTS.items():
        new_total += category_score(counts.get(category, 0), maximum)
    new_total = min(new_total, SEVERITY_MAX_NEW)

    return old_total, new_total, counts


# ============================================================
# INTENSITY -- unchanged constants from post_auth_combined_v3.py
# ============================================================

P50 = 2
P75 = 8
P90 = 28
P95 = 55.75
P99 = 761
MAX_COMMANDS = 13431


def intensity_score(x):
    x = max(0.0, float(x))

    if x <= P50:
        return 0.5 * (x / P50)
    elif x <= P75:
        ratio = (math.log1p(x / P50) - math.log1p(P50 / P50)) / (
            math.log1p(P75 / P50) - math.log1p(P50 / P50)
        )
        return 0.5 + 0.5 * ratio
    elif x <= P90:
        ratio = (math.log1p(x / P75) - math.log1p(P75 / P75)) / (
            math.log1p(P90 / P75) - math.log1p(P75 / P75)
        )
        return 1.0 + 0.5 * ratio
    elif x <= P95:
        ratio = (math.log1p(x / P90) - math.log1p(P90 / P90)) / (
            math.log1p(P95 / P90) - math.log1p(P90 / P90)
        )
        return 1.5 + 1.0 * ratio
    elif x <= P99:
        ratio = (math.log1p(x / P95) - math.log1p(P95 / P95)) / (
            math.log1p(P99 / P95) - math.log1p(P95 / P95)
        )
        return 2.5 + 1.0 * ratio
    else:
        if MAX_COMMANDS <= P99:
            return 5.0
        ratio = math.log1p((x - P99) / P99) / math.log1p((MAX_COMMANDS - P99) / P99)
        return min(5.0, 3.5 + 1.5 * ratio)


# ============================================================
# DIVERSITY -- unchanged constants from post_auth_combined_v3.py
# ============================================================

D_P95 = 3
D_P99 = 14
D_MAX = 17


def diversity_score(x):
    x = max(0, int(x))
    if x <= 1:
        return 0.0
    if x >= D_MAX:
        return 3.0
    points = [(1, 0.0), (D_P95, 1.0), (D_P99, 2.0), (D_MAX, 3.0)]
    for i in range(1, len(points)):
        x0, y0 = points[i - 1]
        x1, y1 = points[i]
        if x <= x1:
            ratio = (math.log1p(x) - math.log1p(x0)) / (math.log1p(x1) - math.log1p(x0))
            return y0 + ratio * (y1 - y0)
    return 3.0


# ============================================================
# RISK LEVEL -- unchanged thresholds, applied to OLD scale (0-15) for
# direct comparability with your existing validated numbers. Also computed
# on the NEW scale (0-18.5) for you to inspect -- NOT auto-adopted as the
# production threshold, since those cutoffs would need the same percentile
# re-derivation you used for everything else. See printed note in main().
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

ip_commands = {}

with open(LOGFILE, newline="", errors="ignore") as fh:
    reader = csv.DictReader(fh)
    for row in reader:
        ip = (row.get("src_ip") or "").strip()
        command = (row.get("command") or "").strip()
        if not ip or not command:
            continue
        ip_commands.setdefault(ip, []).append(command)


# ============================================================
# LOAD FEATURES + SCORE
# ============================================================

rows = []

with open(INPUT, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row["ip"]
        commands = int(float(row["commands"]))
        unique = int(float(row["unique"]))

        old_severity, new_severity, cat_counts = calculate_severity(ip_commands.get(ip, []))
        intensity = intensity_score(commands)
        diversity = diversity_score(unique)

        old_total = old_severity + intensity + diversity
        new_total = new_severity + intensity + diversity

        rows.append({
            "ip": ip,
            "commands": commands,
            "unique": unique,
            "severity_old": old_severity,
            "severity_new": new_severity,
            "intensity": intensity,
            "diversity": diversity,
            "total_old": old_total,
            "total_new": new_total,
            "risk_level_old": risk_level(old_total),
            "risk_level_new": risk_level(new_total),
            "persistence_backdoor_hits": cat_counts.get("persistence_backdoor", 0),
            "dropper_execution_hits": cat_counts.get("dropper_execution", 0),
        })

rows.sort(key=lambda r: r["total_new"], reverse=True)


# ============================================================
# WRITE CSV
# ============================================================

fields = [
    "ip", "commands", "unique",
    "severity_old", "severity_new", "intensity", "diversity",
    "total_old", "total_new", "risk_level_old", "risk_level_new",
    "persistence_backdoor_hits", "dropper_execution_hits",
]

with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "ip": row["ip"],
            "commands": row["commands"],
            "unique": row["unique"],
            "severity_old": f"{row['severity_old']:.4f}",
            "severity_new": f"{row['severity_new']:.4f}",
            "intensity": f"{row['intensity']:.4f}",
            "diversity": f"{row['diversity']:.4f}",
            "total_old": f"{row['total_old']:.4f}",
            "total_new": f"{row['total_new']:.4f}",
            "risk_level_old": row["risk_level_old"],
            "risk_level_new": row["risk_level_new"],
            "persistence_backdoor_hits": row["persistence_backdoor_hits"],
            "dropper_execution_hits": row["dropper_execution_hits"],
        })


# ============================================================
# SUMMARY
# ============================================================

def summarize():
    lines = []
    lines.append("=" * 70)
    lines.append("POST-AUTH COMBINED FINAL (severity/intensity/diversity)")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"IPs analysed        : {len(rows)}")
    lines.append(f"Old scale max       : {SEVERITY_MAX_OLD + 5 + 3} (severity 7 + intensity 5 + diversity 3)")
    lines.append(f"New scale max       : {SEVERITY_MAX_NEW + 5 + 3} (severity {SEVERITY_MAX_NEW} + intensity 5 + diversity 3)")
    lines.append("")

    old_levels = Counter(r["risk_level_old"] for r in rows)
    new_levels = Counter(r["risk_level_new"] for r in rows)

    lines.append("RISK DISTRIBUTION -- OLD (v3, unchanged) vs NEW (with backdoor/dropper patch)")
    lines.append("-" * 70)
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        lines.append(f"{level:10s}: old={old_levels[level]:5d}   new={new_levels[level]:5d}")
    lines.append("")

    moved = [r for r in rows if r["risk_level_old"] != r["risk_level_new"]]
    lines.append(f"IPs whose risk tier CHANGED due to the patch: {len(moved)}")
    lines.append("-" * 70)
    for r in sorted(moved, key=lambda r: r["total_new"], reverse=True)[:30]:
        lines.append(
            f"{r['ip']:18s} {r['risk_level_old']:8s} -> {r['risk_level_new']:8s}  "
            f"(backdoor_hits={r['persistence_backdoor_hits']}, dropper_hits={r['dropper_execution_hits']}, "
            f"total {r['total_old']:.2f} -> {r['total_new']:.2f})"
        )
    lines.append("")

    flagged = [r for r in rows if r["persistence_backdoor_hits"] > 0 or r["dropper_execution_hits"] > 0]
    lines.append(f"IPs matching the new patterns at all: {len(flagged)}")
    lines.append("-" * 70)
    for r in sorted(flagged, key=lambda r: r["total_new"], reverse=True)[:30]:
        lines.append(
            f"{r['ip']:18s} backdoor_hits={r['persistence_backdoor_hits']:3d}  "
            f"dropper_hits={r['dropper_execution_hits']:3d}  "
            f"risk_old={r['risk_level_old']:8s}  risk_new={r['risk_level_new']:8s}"
        )
    lines.append("")

    lines.append("NOTE ON RISK THRESHOLDS")
    lines.append("-" * 70)
    lines.append(
        "risk_level() cutoffs (>=10 CRITICAL, >=7 HIGH, >=4 MEDIUM) were "
        "calibrated on the OLD 0-15 scale and are applied UNCHANGED here to "
        "both total_old and total_new for direct comparability. The new "
        "scale's true ceiling is 18.5, not 15 -- if you want CRITICAL/HIGH "
        "cutoffs that reflect the new scale properly, re-run the same "
        "percentile approach you used for the other features against the "
        "total_new column and update these thresholds deliberately, rather "
        "than trusting this script's untouched carry-over values."
    )

    return "\n".join(lines)


summary_text = summarize()
print(summary_text)

with open(RESULTS, "w") as f:
    f.write(summary_text + "\n")

print()
print(f"Created: {OUTPUT}")
print(f"Created: {RESULTS}")
