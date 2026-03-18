import pandas as pd
import matplotlib.pyplot as plt

# ---------- STYLE ----------
plt.style.use('ggplot')

def setup_plot(title):
    plt.figure(figsize=(12,7))
    plt.title(title)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

def add_values(bars):
    for bar in bars:
        height = bar.get_height()
        plt.annotate(
            str(int(height)),
            xy=(bar.get_x() + bar.get_width()/2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha='center',
            va='bottom',
            fontsize=8
        )

# ---------- LOAD MAIN DATA ----------
df = pd.read_csv("csv/all_logs.csv")

# ---------- TOP 15 COMMANDS ----------
top_commands = df['command'].value_counts().head(15)

setup_plot("Top Commands Used by Attackers")
bars = plt.bar(top_commands.index, top_commands.values)
add_values(bars)

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/commands.png")


# ---------- TOP 15 IPs ----------
top_ips = df['src_ip'].value_counts().head(15)

setup_plot("Top Attacker IPs")
bars = plt.bar(top_ips.index, top_ips.values)
add_values(bars)

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/top_ips.png")


# ---------- TOP 15 USERNAMES ----------
top_usernames = df['username'].value_counts().head(15)

setup_plot("Top Usernames")
bars = plt.bar(top_usernames.index, top_usernames.values)
add_values(bars)

plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/usernames.png")


# ---------- COUNTRIES ----------
countries_df = pd.read_csv("csv/countries.csv")
top_countries = countries_df.head(10)

setup_plot("Top Attacking Countries")
bars = plt.bar(top_countries['Country'], top_countries['Count'])
add_values(bars)

plt.xticks(rotation=45)
plt.subplots_adjust(bottom=0.25)
plt.savefig("images/countries.png")


# ---------- TIMELINE (HOURLY) ----------
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour

timeline = df['hour'].value_counts().sort_index()

setup_plot("Attack Timeline (Hourly)")
bars = plt.bar(timeline.index, timeline.values)
add_values(bars)

plt.xlabel("Hour of Day")
plt.ylabel("Number of Attacks")

plt.savefig("images/timeline.png")


print("✅ Charts updated successfully!")
