import pandas as pd
import matplotlib.pyplot as plt
import os

CSV_DIR = "csv/"
IMG_DIR = "images/"
TOP_N = 10   # ✅ now Top 10

os.makedirs(IMG_DIR, exist_ok=True)


# ---------- GENERIC BAR CHART ----------
def plot_barh(file, label, title, output):
    df = pd.read_csv(file)

    # normalize columns
    df.columns = df.columns.str.strip().str.lower()

    df = df.dropna()
    df = df.head(TOP_N)
    df = df[::-1]

    plt.figure(figsize=(10, 6))
    plt.barh(df[label.lower()], df["count"])

    # values on bars
    for i, v in enumerate(df["count"]):
        plt.text(v + 2, i, str(v), va='center')

    plt.xlabel("Count")
    plt.ylabel(label.capitalize())
    plt.title(title)

    plt.grid(axis="x", linestyle="--", alpha=0.5)

    # clean borders
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(output, dpi=300)
    plt.close()


# ---------- TIMELINE (24 HOURS) ----------
def plot_timeline():
    df = pd.read_csv(f"{CSV_DIR}/all_logs.csv")

    # convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')

    # extract hour
    df["hour"] = df["timestamp"].dt.hour

    # count per hour
    hourly = df["hour"].value_counts().sort_index()

    # ensure full 24 hours
    full_hours = pd.Series(0, index=range(24))
    hourly = full_hours.add(hourly, fill_value=0)

    plt.figure(figsize=(12, 6))
    plt.bar(hourly.index, hourly.values)

    plt.xlabel("Hour of Day (0–23)")
    plt.ylabel("Number of Attacks")
    plt.title("Attack Timeline (24 Hours)")

    plt.xticks(range(24))
    plt.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(f"{IMG_DIR}/timeline.png", dpi=300)
    plt.close()


# ---------- GENERATE ALL CHARTS ----------

# Commands
plot_barh(
    f"{CSV_DIR}/commands.csv",
    "command",
    "Top Commands Used by Attackers",
    f"{IMG_DIR}/commands.png"
)

# Usernames
plot_barh(
    f"{CSV_DIR}/usernames.csv",
    "username",
    "Top Usernames",
    f"{IMG_DIR}/usernames.png"
)

# Passwords
plot_barh(
    f"{CSV_DIR}/passwords.csv",
    "password",
    "Top Passwords",
    f"{IMG_DIR}/passwords.png"
)

# Top IPs
plot_barh(
    f"{CSV_DIR}/top_ips.csv",
    "src_ip",
    "Top Attacking IPs",
    f"{IMG_DIR}/top_ips.png"
)

# ---------- COUNTRIES ----------
try:
    df_c = pd.read_csv(f"{CSV_DIR}/countries.csv")

    df_c.columns = df_c.columns.str.strip()

    df_c = df_c.dropna()
    df_c = df_c.head(TOP_N)
    df_c = df_c[::-1]

    plt.figure(figsize=(10, 6))
    plt.barh(df_c["Country"], df_c["Count"])

    for i, v in enumerate(df_c["Count"]):
        plt.text(v + 2, i, str(v), va='center')

    plt.xlabel("Count")
    plt.ylabel("Country")
    plt.title("Top Attacking Countries")

    plt.grid(axis="x", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(f"{IMG_DIR}/countries.png", dpi=300)
    plt.close()

    print("✅ countries.png generated")

except Exception as e:
    print("❌ countries error:", e)


# ---------- TIMELINE ----------
plot_timeline()

print("✅ All charts generated successfully!")
