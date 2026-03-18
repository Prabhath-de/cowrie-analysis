import pandas as pd
import matplotlib.pyplot as plt

# Load data
df = pd.read_csv("csv/all_logs.csv")

# Top 15 Commands
top_commands = df['command'].value_counts().head(15)

plt.figure()
top_commands.plot(kind='bar')
plt.title("Top Commands Used by Attackers")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/commands.png")

# Top 15 IPs
top_ips = df['src_ip'].value_counts().head(15)

plt.figure()
top_ips.plot(kind='bar')
plt.title("Top Attacker IPs")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/top_ips.png")

# Top 15 Usernames
top_usernames = df['username'].value_counts().head(15)

plt.figure()
top_usernames.plot(kind='bar')
plt.title("Top Usernames")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/usernames.png")

# Top Countries (correct columns)
countries_df = pd.read_csv("csv/countries.csv")

top_countries = countries_df.head(10)

plt.figure(figsize=(10,6))

bars = plt.bar(top_countries['Country'], top_countries['Count'])

for bar in bars:
    height = bar.get_height()
    plt.text(
        bar.get_x() + bar.get_width()/2,
        height,
        int(height),
        ha='center',
        va='bottom',
        fontsize=8
    )

plt.title("Top Attacking Countries")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("images/countries.png")

print("✅ Charts updated successfully!")
