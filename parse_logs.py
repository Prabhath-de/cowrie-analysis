import json
import pandas as pd
import os

log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

data = []

# ---------- CLEAN COMMAND FUNCTION ----------
def extract_command(cmd):
    if not cmd:
        return None

    cmd = cmd.strip()

    # ❌ skip useless redirections
    if ">/dev/null" in cmd:
        return None

    # take first command before ;
    cmd = cmd.split(";")[0]

    # remove path (e.g. /bin/uname → uname)
    cmd = cmd.split("/")[-1]

    # take main command only
    cmd = cmd.split(" ")[0]

    return cmd


# ---------- READ LOG FILE ----------
with open(log_file) as f:
    for line in f:
        try:
            log = json.loads(line)

            # only command input events
            if log.get("eventid") != "cowrie.command.input":
                continue

            raw_cmd = log.get("input")
            clean_cmd = extract_command(raw_cmd)

            # ❌ skip invalid commands
            if not clean_cmd:
                continue

            entry = {
                "timestamp": log.get("timestamp"),
                "src_ip": log.get("src_ip"),
                "username": log.get("username"),
                "password": log.get("password"),
                "command": clean_cmd   # ✅ save CLEAN command
            }

            data.append(entry)

        except:
            continue

# ---------- CREATE DATAFRAME ----------
df = pd.DataFrame(data)

# ---------- SAVE CSV ----------
os.makedirs("csv", exist_ok=True)
df.to_csv("csv/all_logs.csv", index=False)

# ---------- GENERATE STATS ----------
df['command'].value_counts().to_csv("csv/commands.csv")
df['username'].value_counts().to_csv("csv/usernames.csv")
df['password'].value_counts().to_csv("csv/passwords.csv")
df['src_ip'].value_counts().to_csv("csv/top_ips.csv")

print("✅ Logs parsed (clean commands only)!")
