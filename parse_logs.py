import json
import pandas as pd
import os

log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

data = []

with open(log_file) as f:
    for line in f:
        try:
            log = json.loads(line)

            entry = {
                "timestamp": log.get("timestamp"),
                "src_ip": log.get("src_ip"),
                "username": log.get("username"),
                "password": log.get("password"),
                "command": log.get("input")
            }

            data.append(entry)

        except:
            continue

df = pd.DataFrame(data)

# save main log
os.makedirs("csv", exist_ok=True)
df.to_csv("csv/all_logs.csv", index=False)

# other CSVs
df['command'].value_counts().to_csv("csv/commands.csv")
df['username'].value_counts().to_csv("csv/usernames.csv")
df['password'].value_counts().to_csv("csv/passwords.csv")
df['src_ip'].value_counts().to_csv("csv/top_ips.csv")

print("✅ Logs parsed and CSV updated!")
