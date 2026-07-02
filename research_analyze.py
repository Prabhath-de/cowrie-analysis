import pandas as pd
import matplotlib.pyplot as plt
import os

CSV_DIR = "research_csv"
IMG_DIR = "research_images"
TOP_N = 10

os.makedirs(IMG_DIR, exist_ok=True)


# ---------- GENERIC HORIZONTAL BAR CHART ----------
def plot_barh(file, label_col, count_col, title, output):
    df = pd.read_csv(file)

    df = df.dropna()
    df = df.head(TOP_N)
    df = df[::-1]   # reverse for nice top-to-bottom display

    plt.figure(figsize=(10, 6))
    plt.barh(df[label_col], df[count_col])

    for i, v in enumerate(df[count_col]):
        plt.text(v + max(df[count_col]) * 0.01, i, str(v), va='center')

    plt.xlabel("Count")
    plt.ylabel(label_col.replace("_", " ").title())
    plt.title(title)
    plt.grid(axis="x", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(output, dpi=300)
    plt.close()


# ---------- TIMELINE CHART ----------
def plot_timeline():
    df = pd.read_csv(f"{CSV_DIR}/all_logs_full.csv")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # group by date
    daily_counts = df["timestamp"].dt.date.value_counts().sort_index()

    plt.figure(figsize=(14, 6))
    plt.plot(daily_counts.index, daily_counts.values, marker='o')

    plt.xlabel("Date")
    plt.ylabel("Number of Events")
    plt.title("Daily Attack Activity Over Research Period")
    plt.grid(True, linestyle="--", alpha=0.5)

    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{IMG_DIR}/timeline_full.png", dpi=300)
    plt.close()


# ---------- TOP IPS ----------
plot_barh(
    f"{CSV_DIR}/top_ips_full.csv",
    "src_ip",
    "count",
    "Top Attacking IP Addresses",
    f"{IMG_DIR}/top_ips_full.png"
)

# ---------- USERNAMES ----------
plot_barh(
    f"{CSV_DIR}/usernames_full.csv",
    "username",
    "count",
    "Top Targeted Usernames",
    f"{IMG_DIR}/usernames_full.png"
)

# ---------- PASSWORDS ----------
plot_barh(
    f"{CSV_DIR}/passwords_full.csv",
    "password",
    "count",
    "Most Common Passwords Used by Attackers",
    f"{IMG_DIR}/passwords_full.png"
)

# ---------- COMMANDS ----------
plot_barh(
    f"{CSV_DIR}/commands_full.csv",
    "command",
    "count",
    "Most Frequently Executed Commands",
    f"{IMG_DIR}/commands_full.png"
)

# ---------- COUNTRIES ----------
plot_barh(
    f"{CSV_DIR}/countries_full.csv",
    "Country",
    "Count",
    "Top Attacking Countries",
    f"{IMG_DIR}/countries_full.png"
)

# ---------- TIMELINE ----------
plot_timeline()

print("✅ Research charts generated successfully!")

