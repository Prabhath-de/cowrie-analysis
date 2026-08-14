import json
import pandas as pd
import os
import glob

# =========================================================
# RESEARCH DATASET PARSER
# Reads:
#   1) all backup JSON files in backups/
#   2) current live cowrie.json
# Outputs:
#   research_csv/all_logs_full.csv
#   research_csv/top_ips_full.csv
#   research_csv/usernames_full.csv
#   research_csv/passwords_full.csv
#   research_csv/commands_full.csv
#   research_csv/countries_full.csv
# =========================================================

# ---------- PATHS ----------
BACKUP_DIR = "/home/cowrie/cowrie-analysis/backups"
CURRENT_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_DIR = "research_csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

data = []


# ---------- CLEAN COMMAND FUNCTION ----------
def extract_command(cmd):
    if not cmd:
        return None

    cmd = cmd.strip().lower()

    # remove common redirection noise
    cmd = cmd.replace(">/dev/null", "")

    # split multiple commands and keep first
    for sep in [";", "&&", "||"]:
        if sep in cmd:
            cmd = cmd.split(sep)[0]

    # remove quotes
    cmd = cmd.replace('"', '').replace("'", "")

    parts = cmd.split()
    if len(parts) == 0:
        return None

    main_cmd = parts[0]

    # remove path: /bin/uname -> uname
    main_cmd = main_cmd.split("/")[-1]

    invalid = ["", "null", "bin:$path", "$path", "export"]

    if main_cmd in invalid:
        return None

    if main_cmd.startswith("$"):
        return None

    # keep only alphabetic command names
    if not main_cmd.isalpha():
        return None

    return main_cmd


# ---------- FUNCTION TO READ ONE JSON LOG FILE ----------
def process_log_file(log_file):
    rows = []

    if not os.path.exists(log_file):
        print(f"⚠️ File not found: {log_file}")
        return rows

    print(f"📄 Reading: {log_file}")

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                log = json.loads(line)
                event = log.get("eventid")

                # ---------- COMMAND EVENTS ----------
                if event == "cowrie.command.input":
                    raw_cmd = log.get("input")
                    clean_cmd = extract_command(raw_cmd)

                    if not clean_cmd:
                        continue

                    rows.append({
                        "timestamp": log.get("timestamp"),
                        "event": event,
                        "src_ip": log.get("src_ip"),
                        "username": log.get("username"),
                        "password": log.get("password"),
                        "command": clean_cmd,
                        "source_file": os.path.basename(log_file)
                    })

                # ---------- LOGIN EVENTS ----------
                elif event in ["cowrie.login.failed", "cowrie.login.success"]:
                    rows.append({
                        "timestamp": log.get("timestamp"),
                        "event": event,
                        "src_ip": log.get("src_ip"),
                        "username": log.get("username"),
                        "password": log.get("password"),
                        "command": None,
                        "source_file": os.path.basename(log_file)
                    })

            except Exception:
                continue

    return rows


# =========================================================
# 1) READ ALL BACKUP FILES
# =========================================================
backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "cowrie_*.json")))

print(f"🗂 Found {len(backup_files)} backup files")

for bf in backup_files:
    data.extend(process_log_file(bf))


# =========================================================
# 2) READ CURRENT LIVE LOG FILE
# =========================================================
if os.path.exists(CURRENT_LOG):
    data.extend(process_log_file(CURRENT_LOG))
else:
    print(f"⚠️ Current log file not found: {CURRENT_LOG}")


# =========================================================
# 3) CREATE DATAFRAME
# =========================================================
df = pd.DataFrame(data)

if df.empty:
    print("❌ No data found. research_csv files were not generated.")
    exit()

# convert timestamp
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# drop rows without timestamp or src_ip
df = df.dropna(subset=["timestamp", "src_ip"])

# sort by time
df = df.sort_values("timestamp")

# remove exact duplicates
df = df.drop_duplicates()

# save full dataset
df.to_csv(f"{OUTPUT_DIR}/all_logs_full.csv", index=False)


# =========================================================
# 4) GENERATE SUMMARY CSV FILES
# =========================================================

# Top IPs
ips_df = df["src_ip"].value_counts().reset_index()
ips_df.columns = ["src_ip", "count"]
ips_df.to_csv(f"{OUTPUT_DIR}/top_ips_full.csv", index=False)

# Usernames
usernames_df = df["username"].dropna().value_counts().reset_index()
usernames_df.columns = ["username", "count"]
usernames_df.to_csv(f"{OUTPUT_DIR}/usernames_full.csv", index=False)

# Passwords
passwords_df = df["password"].dropna().value_counts().reset_index()
passwords_df.columns = ["password", "count"]
passwords_df.to_csv(f"{OUTPUT_DIR}/passwords_full.csv", index=False)

# Commands
commands_df = df["command"].dropna().value_counts().reset_index()
commands_df.columns = ["command", "count"]
commands_df.to_csv(f"{OUTPUT_DIR}/commands_full.csv", index=False)


# =========================================================
# 5) GEOIP COUNTRIES
# =========================================================
try:
    import geoip2.database

    reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-City.mmdb")

    def get_country(ip):
        try:
            return reader.city(ip).country.name
        except:
            return "Unknown"

    df["country"] = df["src_ip"].apply(get_country)

    countries_df = df["country"].value_counts().reset_index()
    countries_df.columns = ["Country", "Count"]
    countries_df.to_csv(f"{OUTPUT_DIR}/countries_full.csv", index=False)

    print("✅ countries_full.csv generated")

except Exception as e:
    print("⚠️ GeoIP not working:", e)


# =========================================================
# 6) BASIC DATASET SUMMARY
# =========================================================
print("\n================ RESEARCH DATASET SUMMARY ================")
print("Total rows            :", len(df))
print("Unique source IPs     :", df["src_ip"].nunique())
print("Unique dates          :", df["timestamp"].dt.date.nunique())
print("\nEvent counts:")
print(df["event"].value_counts(dropna=False))

print("\nDate range:")
print("Earliest:", df["timestamp"].min())
print("Latest  :", df["timestamp"].max())

print("\nRows per date:")
print(df["timestamp"].dt.date.value_counts().sort_index())

print("\n✅ Research CSV files generated successfully!")
