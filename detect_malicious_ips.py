import pandas as pd

INPUT_FILE = "research_csv/all_logs_full.csv"
OUTPUT_FILE = "research_csv/malicious_ips.csv"

# ---------- LOAD DATA ----------
df = pd.read_csv(INPUT_FILE)

# keep only required columns
df = df[["src_ip", "event"]].dropna(subset=["src_ip", "event"])

# ---------- COUNT EVENTS PER IP ----------
event_counts = (
    df.groupby(["src_ip", "event"])
      .size()
      .unstack(fill_value=0)
      .reset_index()
)

# make sure all needed columns exist
for col in ["cowrie.login.success", "cowrie.login.failed", "cowrie.command.input"]:
    if col not in event_counts.columns:
        event_counts[col] = 0

# rename columns
event_counts = event_counts.rename(columns={
    "cowrie.login.success": "success_count",
    "cowrie.login.failed": "failed_count",
    "cowrie.command.input": "command_count"
})

# total events per IP
event_counts["total_events"] = (
    event_counts["success_count"] +
    event_counts["failed_count"] +
    event_counts["command_count"]
)

# ---------- DETECTION RULES ----------
malicious_rows = []

for _, row in event_counts.iterrows():
    ip = row["src_ip"]
    success_count = row["success_count"]
    failed_count = row["failed_count"]
    command_count = row["command_count"]
    total_events = row["total_events"]

    reason = None

    # Rule A: attacker executed many commands
    if command_count >= 5:
        reason = "command_count >= 5"

    # Rule B: repeated successful access + at least one command
    elif success_count >= 3 and command_count >= 1:
        reason = "success_count >= 3 and command_count >= 1"

    # Rule C: many failed attempts
    elif failed_count >= 10:
        reason = "failed_count >= 10"

    if reason:
        malicious_rows.append({
            "src_ip": ip,
            "success_count": int(success_count),
            "failed_count": int(failed_count),
            "command_count": int(command_count),
            "total_events": int(total_events),
            "malicious_reason": reason
        })

# ---------- SAVE RESULTS ----------
malicious_df = pd.DataFrame(malicious_rows)

if malicious_df.empty:
    print("⚠️ No malicious IPs detected with current rules.")
else:
    malicious_df = malicious_df.sort_values(
        by=["command_count", "success_count", "failed_count"],
        ascending=False
    )
    malicious_df.to_csv(OUTPUT_FILE, index=False)

    print("✅ malicious_ips.csv generated successfully!")
    print(f"Total malicious IPs detected: {len(malicious_df)}")
    print("\nTop 10 malicious IPs:")
    print(malicious_df.head(10).to_string(index=False))
