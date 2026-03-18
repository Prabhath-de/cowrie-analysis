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

print("✅ Charts updated successfully!")
