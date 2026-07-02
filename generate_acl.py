import pandas as pd

INPUT_FILE = "research_csv/malicious_ips.csv"
OUTPUT_FILE = "research_csv/generated_acl_rules.txt"

# how many top malicious IPs to include in ACL
TOP_N = 100

# ---------- LOAD MALICIOUS IP LIST ----------
df = pd.read_csv(INPUT_FILE)

if df.empty:
    print("❌ malicious_ips.csv is empty. No ACL rules generated.")
    exit()

# sort by severity
df = df.sort_values(
    by=["command_count", "success_count", "failed_count"],
    ascending=False
)

# take top N
top_df = df.head(TOP_N)

# ---------- GENERATE ACL RULES ----------
acl_lines = []
acl_lines.append("ip access-list extended HONEYPOT-BLOCKLIST")

for ip in top_df["src_ip"]:
    acl_lines.append(f" deny ip host {ip} any")

acl_lines.append(" permit ip any any")

# ---------- SAVE FILE ----------
with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(acl_lines))

print("✅ generated_acl_rules.txt created successfully!")
print(f"Total IPs included in ACL: {len(top_df)}")
print("\nPreview of ACL rules:\n")
print("\n".join(acl_lines[:15]))   # preview first few lines
