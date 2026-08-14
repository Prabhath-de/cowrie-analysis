"""
research_parse_logs.py -- memory-safe version.

The previous version built one giant Python list of every event across
all 151+ backup files plus the live log, then constructed a single pandas
DataFrame from it. Adding full_command (the intact raw command text,
which can be hundreds of characters for chained attack one-liners) pushed
peak memory past the server's limit and the process got OOM-killed.

This version writes each row directly to the output CSV as it's read,
one file at a time -- memory usage stays roughly constant regardless of
how many backup files or events exist, instead of growing with the total
dataset size. Summary stats (top IPs, usernames, passwords, commands,
countries) are computed with running Counters during the same streaming
pass, so the file never needs to be fully loaded into memory at all.

One deliberate trade-off: the previous version did a global sort-by-
timestamp and an exact-duplicate-row drop, both of which require holding
everything in memory. Neither is needed by the downstream scoring scripts
(they group by src_ip regardless of row order), so both are dropped here.
If you ever need the CSV strictly time-sorted, that can be done afterward
with the Unix `sort` command directly on the file, without touching
Python memory at all.
"""

import json
import os
import glob
import csv
from collections import Counter

BACKUP_DIR = "/home/cowrie/cowrie-analysis/backups"
CURRENT_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_DIR = "research_csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

FIELDNAMES = ["timestamp", "event", "src_ip", "username", "password",
              "command", "full_command", "source_file"]


def extract_command(cmd):
    if not cmd:
        return None
    cmd = cmd.strip().lower()
    cmd = cmd.replace(">/dev/null", "")
    for sep in [";", "&&", "||"]:
        if sep in cmd:
            cmd = cmd.split(sep)[0]
    cmd = cmd.replace('"', '').replace("'", "")
    parts = cmd.split()
    if len(parts) == 0:
        return None
    main_cmd = parts[0]
    main_cmd = main_cmd.split("/")[-1]
    invalid = ["", "null", "bin:$path", "$path", "export"]
    if main_cmd in invalid:
        return None
    if main_cmd.startswith("$"):
        return None
    if not main_cmd.isalpha():
        return None
    return main_cmd


# ---------------------------------------------------------
# Running counters -- replace the old "load everything into
# a DataFrame, then .value_counts()" approach
# ---------------------------------------------------------

ip_counter = Counter()
username_counter = Counter()
password_counter = Counter()
command_counter = Counter()
event_counter = Counter()
dates_seen = set()

total_rows = 0
earliest_ts = None
latest_ts = None

seen_signatures = set()  # lightweight dedup: (timestamp, event, src_ip, full_command)


def process_log_file(log_file, writer):
    global total_rows, earliest_ts, latest_ts

    if not os.path.exists(log_file):
        print(f"WARNING File not found: {log_file}")
        return

    print(f"Reading: {log_file}")
    rows_this_file = 0

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                log = json.loads(line)
                event = log.get("eventid")
                ts = log.get("timestamp")
                src_ip = log.get("src_ip")

                if not ts or not src_ip:
                    continue

                if event == "cowrie.command.input":
                    raw_cmd = log.get("input")
                    clean_cmd = extract_command(raw_cmd)
                    row = {
                        "timestamp": ts,
                        "event": event,
                        "src_ip": src_ip,
                        "username": log.get("username"),
                        "password": log.get("password"),
                        "command": clean_cmd,
                        "full_command": raw_cmd,
                        "source_file": os.path.basename(log_file),
                    }
                elif event in ("cowrie.login.failed", "cowrie.login.success"):
                    row = {
                        "timestamp": ts,
                        "event": event,
                        "src_ip": src_ip,
                        "username": log.get("username"),
                        "password": log.get("password"),
                        "command": None,
                        "full_command": None,
                        "source_file": os.path.basename(log_file),
                    }
                else:
                    continue

                sig = (ts, event, src_ip, row["full_command"])
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                writer.writerow(row)
                rows_this_file += 1
                total_rows += 1

                event_counter[event] += 1
                ip_counter[src_ip] += 1
                if row["username"]:
                    username_counter[row["username"]] += 1
                if row["password"]:
                    password_counter[row["password"]] += 1
                if row["command"]:
                    command_counter[row["command"]] += 1

                date_part = ts[:10]  # "2026-03-30T..." -> "2026-03-30"
                dates_seen.add(date_part)
                if earliest_ts is None or ts < earliest_ts:
                    earliest_ts = ts
                if latest_ts is None or ts > latest_ts:
                    latest_ts = ts

            except Exception:
                continue

    print(f"  -> {rows_this_file} rows written")


# =========================================================
# MAIN
# =========================================================

out_path = f"{OUTPUT_DIR}/all_logs_full.csv"

with open(out_path, "w", newline="", encoding="utf-8") as out_f:
    writer = csv.DictWriter(out_f, fieldnames=FIELDNAMES)
    writer.writeheader()

    backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "cowrie_*.json")))
    print(f"Found {len(backup_files)} backup files")

    for bf in backup_files:
        process_log_file(bf, writer)

    if os.path.exists(CURRENT_LOG):
        process_log_file(CURRENT_LOG, writer)
    else:
        print(f"WARNING Current log file not found: {CURRENT_LOG}")

if total_rows == 0:
    print("No data found. research_csv files were not generated.")
    raise SystemExit(0)

# ---------------------------------------------------------
# Summary CSVs -- built from the running counters, no need
# to re-read all_logs_full.csv or use pandas at all
# ---------------------------------------------------------

with open(f"{OUTPUT_DIR}/top_ips_full.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["src_ip", "count"])
    for ip, count in ip_counter.most_common():
        w.writerow([ip, count])

with open(f"{OUTPUT_DIR}/usernames_full.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["username", "count"])
    for u, count in username_counter.most_common():
        w.writerow([u, count])

with open(f"{OUTPUT_DIR}/passwords_full.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["password", "count"])
    for p, count in password_counter.most_common():
        w.writerow([p, count])

with open(f"{OUTPUT_DIR}/commands_full.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["command", "count"])
    for c, count in command_counter.most_common():
        w.writerow([c, count])

# ---------------------------------------------------------
# GeoIP -- looked up once PER UNIQUE IP (cached), not once
# per row, since many rows share the same src_ip
# ---------------------------------------------------------

try:
    import geoip2.database
    reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-City.mmdb")

    country_counter = Counter()
    geo_cache = {}

    def get_country(ip):
        if ip not in geo_cache:
            try:
                geo_cache[ip] = reader.city(ip).country.name
            except Exception:
                geo_cache[ip] = "Unknown"
        return geo_cache[ip]

    for ip, count in ip_counter.items():
        country_counter[get_country(ip)] += count

    with open(f"{OUTPUT_DIR}/countries_full.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Country", "Count"])
        for country, count in country_counter.most_common():
            w.writerow([country, count])

    print("countries_full.csv generated")
except Exception as e:
    print("GeoIP not working:", e)


# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------

print("\n================ RESEARCH DATASET SUMMARY ================")
print("Total rows            :", total_rows)
print("Unique source IPs     :", len(ip_counter))
print("Unique dates          :", len(dates_seen))
print("\nEvent counts:")
for event, count in event_counter.most_common():
    print(f"  {event}: {count}")
print("\nDate range:")
print("Earliest:", earliest_ts)
print("Latest  :", latest_ts)
print("\nResearch CSV files generated successfully!")
