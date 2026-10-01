import sys, math
import pandas as pd
from collections import defaultdict, Counter

sys.path.insert(0, "..")
from detect_advanced_patterns import (
    has_ssh_backdoor_pattern,
    has_dropper_oneliner_pattern,
    has_staged_dropper_pattern,
    has_staged_ssh_backdoor_pattern,
)

SEVERITY_MAX_OLD = 7.0
WEIGHTS = {
    "basic_recon": 0.5, "system_recon": 0.5, "file_modification": 1.0,
    "download_transfer": 1.0, "persistence": 1.5, "account_privilege": 1.5,
    "remote_access_execution": 1.0,
}
NEW_WEIGHTS = {"persistence_backdoor": 2.0, "dropper_execution": 1.5}
SEVERITY_MAX_NEW = SEVERITY_MAX_OLD + sum(NEW_WEIGHTS.values())

COMMANDS = {
    "basic_recon": {"uname","hostname","pwd","whoami","id","ls","env","history","uptime","which"},
    "system_recon": {"ps","top","df","free","lscpu","lspci","ifconfig","ip","netstat","ss","mount","nproc","ulimit","locate"},
    "file_modification": {"rm","chmod","touch"},
    "download_transfer": {"wget","curl","scp"},
    "persistence": {"crontab","systemctl","nohup"},
    "account_privilege": {"useradd","usermod","sudo"},
    "remote_access_execution": {"ssh","sh","nc"},
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

LOGFILE = "../research_csv/all_logs_full.csv"
CALIB_START = pd.Timestamp("2026-03-18T00:00:00Z")
CALIB_END   = pd.Timestamp("2026-06-30T00:00:00Z")
HOLD_END    = pd.Timestamp("2026-08-15T00:00:00Z")
BURST_WINDOW_SECONDS = 5
BURST_THRESHOLD = 10

print("Loading all_logs_full.csv ...")
df = pd.read_csv(LOGFILE, low_memory=False)
df = df[df["event"] == "cowrie.command.input"].copy()
df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
df = df.dropna(subset=["ts", "src_ip"])
df["full_command"] = df["full_command"].fillna("")
df["command"] = df["command"].fillna("")

calib = df[(df["ts"] >= CALIB_START) & (df["ts"] < CALIB_END)].copy()
hold  = df[(df["ts"] >= CALIB_END)   & (df["ts"] < HOLD_END)].copy()

print(f"Calibration events: {len(calib)}  unique IPs: {calib['src_ip'].nunique()}")
print(f"Holdout events:     {len(hold)}  unique IPs: {hold['src_ip'].nunique()}")

def build_ip_table(events):
    ip_commands = defaultdict(list)
    for ip, cmd, full_cmd in zip(events["src_ip"], events["command"], events["full_command"]):
        ip_commands[ip].append({"command": cmd, "full_command": full_cmd})
    commands_count = events.groupby("src_ip").size()
    unique_count = events.groupby("src_ip")["command"].nunique()
    burst = {}
    for ip, grp in events.sort_values("ts").groupby("src_ip"):
        times = (grp["ts"].astype("int64") // 10**9).tolist()
        left = 0
        max_count = 1
        for right in range(len(times)):
            while times[right] - times[left] > BURST_WINDOW_SECONDS:
                left += 1
            max_count = max(max_count, right - left + 1)
        burst[ip] = max_count
    return ip_commands, commands_count, unique_count, burst

calib_ip_cmds, calib_cmds, calib_uniq, calib_burst = build_ip_table(calib)
hold_ip_cmds, hold_cmds, hold_uniq, hold_burst = build_ip_table(hold)

def pct(values, p):
    values = sorted(values)
    if not values:
        return 0.0
    i = (len(values) - 1) * p / 100
    lo = int(i); hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return float(values[lo])
    return float(values[lo] + (values[hi] - values[lo]) * (i - lo))

P50 = pct(calib_cmds.values, 50)
P75 = pct(calib_cmds.values, 75)
P90 = pct(calib_cmds.values, 90)
P95 = pct(calib_cmds.values, 95)
P99 = pct(calib_cmds.values, 99)
MAX_COMMANDS = max(calib_cmds.values)
D_P95 = pct(calib_uniq.values, 95)
D_P99 = pct(calib_uniq.values, 99)
D_MAX = max(calib_uniq.values)

print()
print("Recalculated intensity constants (104-day calibration):")
print(f"  P50={P50} P75={P75} P90={P90} P95={P95} P99={P99} MAX={MAX_COMMANDS}")
print("Recalculated diversity constants (104-day calibration):")
print(f"  D_P95={D_P95} D_P99={D_P99} D_MAX={D_MAX}")

def intensity_score(x):
    x = max(0.0, float(x))
    if x <= P50:
        return 0.5 * (x / P50) if P50 else 0.0
    elif x <= P75:
        r = (math.log1p(x/P50)-math.log1p(1))/(math.log1p(P75/P50)-math.log1p(1))
        return 0.5 + 0.5*r
    elif x <= P90:
        r = (math.log1p(x/P75)-math.log1p(1))/(math.log1p(P90/P75)-math.log1p(1))
        return 1.0 + 0.5*r
    elif x <= P95:
        r = (math.log1p(x/P90)-math.log1p(1))/(math.log1p(P95/P90)-math.log1p(1))
        return 1.5 + 1.0*r
    elif x <= P99:
        r = (math.log1p(x/P95)-math.log1p(1))/(math.log1p(P99/P95)-math.log1p(1))
        return 2.5 + 1.0*r
    else:
        if MAX_COMMANDS <= P99:
            return 5.0
        r = math.log1p((x-P99)/P99)/math.log1p((MAX_COMMANDS-P99)/P99)
        return min(5.0, 3.5+1.5*r)

def diversity_score(x):
    x = max(0, int(x))
    if x <= 1:
        return 0.0
    if x >= D_MAX:
        return 3.0
    points = [(1,0.0),(D_P95,1.0),(D_P99,2.0),(D_MAX,3.0)]
    for i in range(1,len(points)):
        x0,y0 = points[i-1]; x1,y1 = points[i]
        if x <= x1:
            r = (math.log1p(x)-math.log1p(x0))/(math.log1p(x1)-math.log1p(x0))
            return y0 + r*(y1-y0)
    return 3.0

def score_period(ip_cmds, commands, unique, burst):
    rows = []
    for ip in commands.index:
        old_sev, new_sev, _ = calculate_severity(ip_cmds.get(ip, []))
        inten = intensity_score(commands[ip])
        divers = diversity_score(unique[ip])
        total_new = new_sev + inten + divers
        rows.append({
            "ip": ip, "commands": commands[ip], "unique": unique[ip],
            "severity_new": new_sev, "intensity": inten, "diversity": divers,
            "total_new": total_new, "burst": burst.get(ip, 0),
        })
    return rows

calib_rows = score_period(calib_ip_cmds, calib_cmds, calib_uniq, calib_burst)
hold_rows = score_period(hold_ip_cmds, hold_cmds, hold_uniq, hold_burst)

calib_scores = sorted(r["total_new"] for r in calib_rows)
threshold = pct(calib_scores, 99.5)

print()
print(f"Calibration IPs: {len(calib_rows)}")
print(f"Calibration score P50={pct(calib_scores,50):.4f} P75={pct(calib_scores,75):.4f} "
      f"P90={pct(calib_scores,90):.4f} P95={pct(calib_scores,95):.4f} "
      f"P99={pct(calib_scores,99):.4f} P99.5={threshold:.4f}")

calib_candidates = [r for r in calib_rows if r["total_new"] >= threshold and r["burst"] >= BURST_THRESHOLD]
hold_candidates = [r for r in hold_rows if r["total_new"] >= threshold and r["burst"] >= BURST_THRESHOLD]

print()
print(f"FINAL THRESHOLD (P99.5 of 104-day calibration total_new): {threshold:.4f}")
print(f"Calibration candidates (score>=thr AND burst>=10): {len(calib_candidates)}")
print(f"Holdout candidates     (score>=thr AND burst>=10): {len(hold_candidates)}")

with open("recalibration_results.txt", "w") as f:
    f.write(f"Calibration IPs: {len(calib_rows)}\n")
    f.write(f"Holdout IPs: {len(hold_rows)}\n")
    f.write(f"Recalculated threshold (P99.5): {threshold:.4f}\n")
    f.write(f"Calibration candidates: {len(calib_candidates)}\n")
    f.write(f"Holdout candidates: {len(hold_candidates)}\n")
    f.write("\nCalibration candidates:\n")
    for r in sorted(calib_candidates, key=lambda r: r["total_new"], reverse=True):
        f.write(f"  {r['ip']:18s} score={r['total_new']:.4f} burst={r['burst']}\n")
    f.write("\nHoldout candidates:\n")
    for r in sorted(hold_candidates, key=lambda r: r["total_new"], reverse=True):
        f.write(f"  {r['ip']:18s} score={r['total_new']:.4f} burst={r['burst']}\n")

print("\nSaved: recalibration_results.txt")
