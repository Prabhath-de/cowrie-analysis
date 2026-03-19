import json
import pandas as pd
import os

# ---------- FILE PATH ----------
log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

data = []

# ---------- CLEAN COMMAND FUNCTION ----------
def extract_command(cmd):
    if not cmd:
        return None

    cmd = cmd.strip().lower()

    # remove redirection
    cmd = cmd.replace(">/dev/null", "")

    # split multiple commands
    cmd = cmd.split(";")[0]

    # remove quotes
    cmd = cmd.replace('"', '').replace("'", "")

    # split parts
    parts = cmd.split()
    if len(parts) == 0:
        return None

    main_cmd = parts[0]

    # remove path
    main_cmd = main_cmd.split("/")[-1]

    # ❌ remove garbage commands
    invalid = ["", "null", "bin:$path", "$path", "sh", "bash"]

    if main_cmd in invalid:
        return None

    if ":" in main_cmd or "$" in main_cmd:
        return None

    return main_cmd


# ---------- READ LOG FILE ----------
with open(log_file) as f:
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

                entry = {
                    "timestamp": log.get("timestamp"),
                    "src_ip": log.get("src_ip"),
                    "username": log.get("username"),
                    "password": log.get("password"),
                    "command": clean_cmd
                }

                data.append(entry)

            # ---------- LOGIN EVENTS ----------
            elif event == "cowrie.login.failed" or event == "cowrie.login.success":

                entry = {
                    "timestamp": log.get("timestamp"),
                    "src_ip": log.get("src_ip"),
                    "username": log.get("username"),
                    "password": log.get("password"),
                    "command": None
                }

                data.append(entry)

        except:
            continue


# ---------- CREATE DATAFRAME ----------
df = pd.DataFrame(data)

# ---------- CREATE FOLDER ----------
os.makedirs("csv", exist_ok=True)

# ---------- SAVE MAIN LOG ----------
df.to_csv("csv/all_logs.csv", index=False)


# ---------- GENERATE CLEAN STATS ----------

# Commands
commands = df['command'].dropna().value_counts()
commands_df = commands.reset_index()
commands_df.columns = ['command', 'count']
commands_df.to_csv("csv/commands.csv", index=False)

# Usernames
usernames = df['username'].dropna().value_counts()
usernames_df = usernames.reset_index()
usernames_df.columns = ['username', 'count']
usernames_df.to_csv("csv/usernames.csv", index=False)

# Passwords
passwords = df['password'].dropna().value_counts()
passwords_df = passwords.reset_index()
passwords_df.columns = ['password', 'count']
passwords_df.to_csv("csv/passwords.csv", index=False)

# Top IPs
ips = df['src_ip'].dropna().value_counts()
ips_df = ips.reset_index()
ips_df.columns = ['src_ip', 'count']
ips_df.to_csv("csv/top_ips.csv", index=False)


# ---------- GEOIP COUNTRIES ----------
try:
    import geoip2.database

    reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-City.mmdb")

    def get_country(ip):
        try:
            return reader.city(ip).country.name
        except:
            return "Unknown"

    df["country"] = df["src_ip"].apply(get_country)

    countries = df['country'].value_counts()
    countries_df = countries.reset_index()
    countries_df.columns = ['Country', 'Count']
    countries_df.to_csv("csv/countries.csv", index=False)

    print("✅ GeoIP countries generated")

except Exception as e:
    print("⚠️ GeoIP not working:", e)


print("✅ Logs parsed (clean + structured)!")
