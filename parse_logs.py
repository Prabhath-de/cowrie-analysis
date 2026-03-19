import json
import pandas as pd
import os
import re

log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

data = []

# ---------- CLEAN COMMAND FUNCTION ----------
def clean_command(cmd):
    if not cmd:
        return None

    cmd = cmd.strip().lower()

    # remove everything after ;
    cmd = cmd.split(";")[0]

    # remove variables ($...)
    cmd = re.sub(r"\$[a-zA-Z_]+", "", cmd)

    # remove paths
    cmd = cmd.replace("/bin/", "").replace("/usr/bin/", "")
    cmd = cmd.replace("./", "")

    # remove symbols
    cmd = re.sub(r"[^a-z0-9_\- ]", "", cmd)

    # get base command
    cmd = cmd.split(" ")[0]

    # ignore useless
    ignore = ["cd", "pwd", "clear", "export", "echo", "hostname"]

    if cmd in ignore or cmd == "":
        return None

    return cmd


# ---------- READ LOG FILE ----------
with open(log_file) as f:
    for line in f:
        try:
            log = json.loads(line)

            if log.get("eventid") != "cowrie.command.input":
                continue

            raw_cmd = log.get("input")
            clean_cmd = clean_command(raw_cmd)

            if not clean_cmd:
                continue

            data.append({
                "timestamp": log.get("timestamp"),
                "src_ip": log.get("src_ip"),
                "username": log.get("username"),
                "password": log.get("password"),
                "command": clean_cmd
            })

        except:
            continue


# ---------- CREATE DATAFRAME ----------
df = pd.DataFrame(data)

os.makedirs("csv", exist_ok=True)

# save full logs
df.to_csv("csv/all_logs.csv", index=False)

# ---------- SAVE CLEAN STATS ----------
def save_counts(column, filename):
    counts = df[column].value_counts().reset_index()
    counts.columns = [column, "count"]
    counts.to_csv(f"csv/{filename}", index=False)


save_counts("command", "commands.csv")
save_counts("username", "usernames.csv")
save_counts("password", "passwords.csv")
save_counts("src_ip", "top_ips.csv")

print("✅ Logs parsed (clean + structured)!")
