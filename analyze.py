import pandas as pd
import matplotlib.pyplot as plt

# ---------- STYLE ----------
plt.style.use('ggplot')

def setup_plot(title):
    plt.figure(figsize=(12,7))
    plt.title(title)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

# ---------- LOAD DATA ----------
df = pd.read_csv("csv/all_logs.csv")

# ---------- TOP COMMANDS ----------
top_commands = df['command'].value_counts().head(15)

setup_plot("Top Commands Used by Attackers")
plt.bar(top_commands.index, top_commands.values, color='steelblue')

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/commands.png")


# ---------- TOP IPs ----------
top_ips = df['src_ip'].value_counts().head(15)

setup_plot("Top Attacker IPs")
plt.bar(top_ips.index, top_ips.values, color='steelblue')

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/top_ips.png")


# ---------- TOP USERNAMES ----------
top_usernames = df['username'].value_counts().head(15)

setup_plot("Top Usernames")
plt.bar(top_usernames.index, top_usernames.values, color='steelblue')

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/usernames.png")


# ---------- COUNTRIES ----------
countries_df = pd.read_csv("csv/countries.csv")
top_countries = countries_df.head(10)

setup_plot("Top Attacking Countries")
plt.bar(top_countries['Country'], top_countries['Count'], color='steelblue')

plt.xticks(rotation=45)
plt.subplots_adjust(bottom=0.25)
plt.savefig("images/countries.png")


# ---------- TIMELINE ----------
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour

timeline = df['hour'].value_counts().sort_index()

setup_plot("Attack Timeline (Hourly)")
plt.bar(timeline.index, timeline.values, color='steelblue')

plt.xlabel("Hour of Day")
plt.ylabel("Number of Attacks")

plt.tight_layout()
plt.savefig("images/timeline.png")


print("✅ Charts updated successfully!")
