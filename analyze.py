import pandas as pd
import matplotlib.pyplot as plt
import textwrap

# ---------- FIX: disable math parsing ----------
plt.rcParams['text.usetex'] = False

# ---------- GLOBAL STYLE ----------
plt.style.use('default')

def setup_plot(title, xlabel="", ylabel=""):
    plt.figure(figsize=(12,7))
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True, linestyle='--', alpha=0.6)

# ---------- LOAD DATA ----------
df = pd.read_csv("csv/all_logs.csv")

# ---------- TIMELINE ----------
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
df['hour'] = df['timestamp'].dt.hour

timeline = df['hour'].value_counts().sort_index()

setup_plot("Attack Timeline (Hourly)", "Hour of Day", "Number of Attacks")
plt.bar(timeline.index, timeline.values, color='#2E6F9E')

plt.tight_layout()
plt.savefig("images/timeline.png")
plt.close()


# ---------- TOP COMMANDS (CLEANED) ----------

def clean_command(cmd):
    if pd.isna(cmd):
        return None   # ❗ not "unknown"

    # take first command
    cmd = cmd.split(";")[0]

    return cmd.strip()

def clean_command(cmd):
    if pd.isna(cmd):
        return None

    # only first word (best)
    return cmd.split(" ")[0]

top_commands = df['clean_command'].value_counts().head(15)

setup_plot("Top Commands Used by Attackers", "", "Count")

# 🔥 escape $ and wrap text
labels = [cmd.replace('$', r'\$') for cmd in top_commands.index]
labels = [textwrap.fill(cmd, 40) for cmd in labels]

# 🔥 SINGLE plot only
plt.barh(range(len(top_commands)), top_commands.values, color='#2E6F9E')
plt.yticks(range(len(labels)), labels)

# better spacing
plt.subplots_adjust(left=0.4)

plt.tight_layout()
plt.savefig("images/commands.png")
plt.close()





# 🔥 escape $ and wrap text
labels = [cmd.replace('$', r'\$') for cmd in top_commands.index]
labels = [textwrap.fill(cmd, 40) for cmd in labels]

plt.barh(range(len(top_commands)), top_commands.values, color='#2E6F9E')
plt.yticks(range(len(labels)), labels)

# 🔥 fix left spacing
plt.subplots_adjust(left=0.4)

plt.tight_layout()
plt.savefig("images/commands.png")
plt.close()


# ---------- TOP IPs ----------
top_ips = df['src_ip'].value_counts().head(15)

setup_plot("Top Attacker IPs", "", "Count")

plt.bar(range(len(top_ips)), top_ips.values, color='#2E6F9E')
plt.xticks(range(len(top_ips)), top_ips.index, rotation=60, ha='right')

plt.tight_layout()
plt.savefig("images/top_ips.png")
plt.close()


# ---------- TOP USERNAMES ----------
top_usernames = df['username'].value_counts().head(15)

setup_plot("Top Usernames", "", "Count")

plt.bar(range(len(top_usernames)), top_usernames.values, color='#2E6F9E')
plt.xticks(range(len(top_usernames)), top_usernames.index, rotation=45, ha='right')

plt.tight_layout()
plt.savefig("images/usernames.png")
plt.close()


# ---------- COUNTRIES ----------
countries_df = pd.read_csv("csv/countries.csv")
top_countries = countries_df.head(10)

setup_plot("Top Attacking Countries", "", "Count")

plt.bar(range(len(top_countries)), top_countries['Count'], color='#2E6F9E')
plt.xticks(range(len(top_countries)), top_countries['Country'], rotation=45, ha='right')

plt.tight_layout()
plt.savefig("images/countries.png")
plt.close()


print("✅ All charts generated successfully!")
