"""
live_attack_monitor.py

Live, continuously-running behavioral monitor. Uses the EXACT validated
severity/intensity/diversity functions and constants from
post_auth_scoring_final.py (copied verbatim below, not re-derived --
see Chapter 5/6 for the calibration/validation of these functions),
plus a live-computed burst metric (max commands in any 5-second sliding
window), and applies the final published decision rule from
temporal_decision_final.py: score >= 8.5669 AND burst >= 10 ->
ACL_BLOCK_CANDIDATE.

post_auth_scoring_final.py itself is NOT imported, because it executes
a full batch run at module level with no __main__ guard. The pattern
detection functions ARE imported from detect_advanced_patterns.py,
which is a pure function module with no such side effect.

New ACL_BLOCK_CANDIDATE IPs are appended to the SAME
cisco_acl_candidates_final.txt file that watcher_vps.py (running on
the CML controller) already polls -- no changes needed there.
"""

import json
import math
import time
import os
import sys
from collections import Counter
from datetime import datetime

sys.path.insert(0, "/home/cowrie/cowrie-analysis")
from detect_advanced_patterns import (
    has_ssh_backdoor_pattern,
    has_dropper_oneliner_pattern,
    has_staged_dropper_pattern,
    has_staged_ssh_backdoor_pattern,
)

LOGFILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
ACL_FILE = "/home/cowrie/cowrie-analysis/scoring/cisco_acl_candidates_final.txt"
SCORE_THRESHOLD = 8.5669
BURST_THRESHOLD = 10
POLL_INTERVAL = 3

# ============================================================
# VERBATIM from post_auth_scoring_final.py (Chapter 5/6 validated)
# ============================================================

SEVERITY_MAX_OLD = 7.0

WEIGHTS = {
    "basic_recon": 0.5,
    "system_recon": 0.5,
    "file_modification": 1.0,
    "download_transfer": 1.0,
    "persistence": 1.5,
    "account_privilege": 1.5,
    "remote_access_execution": 1.0,
}

NEW_WEIGHTS = {
    "persistence_backdoor": 2.0,
    "dropper_execution": 1.5,
}

SEVERITY_MAX_NEW = SEVERITY_MAX_OLD + sum(NEW_WEIGHTS.values())

COMMANDS = {
    "basic_recon": {"uname", "hostname", "pwd", "whoami", "id", "ls", "env", "history", "uptime", "which"},
    "system_recon": {"ps", "top", "df", "free", "lscpu", "lspci", "ifconfig", "ip", "netstat", "ss", "mount", "nproc", "ulimit", "locate"},
    "file_modification": {"rm", "chmod", "touch"},
    "download_transfer": {"wget", "curl", "scp"},
    "persistence": {"crontab", "systemctl", "nohup"},
    "account_privilege": {"useradd", "usermod", "sudo"},
    "remote_access_execution": {"ssh", "sh", "nc"},
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
    repetition = min(math.log1p(count) / math.log1p(50), 1.0)
    bonus = maximum * 0.50 * repetition
    return base + bonus


def calculate_severity(command_data):
    counts = Counter()
    full_texts = []
    for entry in command_data:
        command = entry["command"]
        full_command = entry["full_command"]
        full_texts.append(full_command)

        category = get_category(command)
        if category:
            counts[category] += 1

        if has_ssh_backdoor_pattern(full_command):
            counts["persistence_backdoor"] += 1
        if has_dropper_oneliner_pattern(full_command):
            counts["dropper_execution"] += 1

    if has_staged_dropper_pattern(full_texts):
        counts["dropper_execution"] += 1
    if has_staged_ssh_backdoor_pattern(full_texts):
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
        ratio = (math.log1p(x / P50) - math.log1p(P50 / P50)) / (math.log1p(P75 / P50) - math.log1p(P50 / P50))
        return 0.5 + 0.5 * ratio
    elif x <= P90:
        ratio = (math.log1p(x / P75) - math.log1p(P75 / P75)) / (math.log1p(P90 / P75) - math.log1p(P75 / P75))
        return 1.0 + 0.5 * ratio
    elif x <= P95:
        ratio = (math.log1p(x / P90) - math.log1p(P90 / P90)) / (math.log1p(P95 / P90) - math.log1p(P90 / P90))
        return 1.5 + 1.0 * ratio
    elif x <= P99:
        ratio = (math.log1p(x / P95) - math.log1p(P95 / P95)) / (math.log1p(P99 / P95) - math.log1p(P95 / P95))
        return 2.5 + 1.0 * ratio
    else:
        if MAX_COMMANDS <= P99:
            return 5.0
        ratio = math.log1p((x - P99) / P99) / math.log1p((MAX_COMMANDS - P99) / P99)
        return min(5.0, 3.5 + 1.5 * ratio)


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
# LIVE-SPECIFIC: burst metric + unique-token count + file monitoring
# ============================================================

def compute_burst(timestamps):
    """Max number of commands within any 5-second sliding window."""
    timestamps = sorted(timestamps)
    max_count = 0
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > 5.0:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


def compute_unique(command_data):
    tokens = set()
    for entry in command_data:
        cmd = (entry["command"] or "").strip()
        if not cmd:
            continue
        token = cmd.split()[0].split("/")[-1]
        tokens.add(token)
    return len(tokens)


def parse_timestamp(ts_str):
    try:
        return datetime.strptime(ts_str[:26], "%Y-%m-%dT%H:%M:%S.%f").timestamp()
    except Exception:
        try:
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        except Exception:
            return None


def load_already_blocked():
    ips = set()
    if os.path.exists(ACL_FILE):
        with open(ACL_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("deny tcp host"):
                    ips.add(line.split()[3])
    return ips


def append_block(ip):
    if not os.path.exists(ACL_FILE):
        print(f"ACL file not found: {ACL_FILE}", flush=True)
        return
    with open(ACL_FILE) as f:
        lines = f.readlines()
    new_lines = []
    inserted = False
    for line in lines:
        if line.strip() == "permit ip any any" and not inserted:
            new_lines.append(f" deny tcp host {ip} any eq 22\n")
            inserted = True
        new_lines.append(line)
    if not inserted:
        new_lines.append(f" deny tcp host {ip} any eq 22\n")
    with open(ACL_FILE, "w") as f:
        f.writelines(new_lines)
    print(f"[{time.strftime('%H:%M:%S')}] APPENDED TO ACL FILE: {ip}", flush=True)


ip_commands = {}
already_blocked = set()


def process_new_events(f):
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("eventid") != "cowrie.command.input":
            continue
        ip = d.get("src_ip")
        full_command = (d.get("input") or "").strip()
        ts_raw = d.get("timestamp")
        if not ip or not full_command or not ts_raw:
            continue
        ts = parse_timestamp(ts_raw)
        if ts is None:
            continue
        ip_commands.setdefault(ip, []).append({
            "command": full_command,
            "full_command": full_command,
            "ts": ts,
        })


def evaluate_and_block():
    for ip, cmds in list(ip_commands.items()):
        if ip in already_blocked:
            continue
        old_sev, new_sev, cat_counts = calculate_severity(cmds)
        intensity = intensity_score(len(cmds))
        diversity = diversity_score(compute_unique(cmds))
        total = new_sev + intensity + diversity
        burst = compute_burst([c["ts"] for c in cmds])
        if int(time.time()) % 10 == 0:
            print(f"  [monitor] {ip}: commands={len(cmds)} score={total:.3f} burst={burst}", flush=True)
        if total >= SCORE_THRESHOLD and burst >= BURST_THRESHOLD:
            print(f"[{time.strftime('%H:%M:%S')}] THRESHOLD CROSSED: {ip} score={total:.4f} burst={burst} -> ACL_BLOCK_CANDIDATE", flush=True)
            append_block(ip)
            already_blocked.add(ip)


def main():
    global already_blocked
    already_blocked = load_already_blocked()
    print(f"Live attack monitor started. Already-blocked IPs loaded: {len(already_blocked)}", flush=True)
    print(f"Threshold: score >= {SCORE_THRESHOLD} AND burst >= {BURST_THRESHOLD}", flush=True)
    print(f"Watching: {LOGFILE}", flush=True)

    with open(LOGFILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            process_new_events(f)
            evaluate_and_block()
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
