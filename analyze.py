import pandas as pd
import matplotlib.pyplot as plt
import os

CSV_DIR = "csv/"
IMG_DIR = "images/"
TOP_N = 10

os.makedirs(IMG_DIR, exist_ok=True)


# ---------- GENERIC BAR CHART FUNCTION ----------
def plot_barh(file, label, title, output):
    df = pd.read_csv(file)

    # remove empty rows
    df = df.dropna()

    # take top N
    df = df.head(TOP_N)

    # reverse for horizontal chart
    df = df[::-1]

    plt.figure(figsize=(10, 6))
    bars = plt.barh(df[label], df["count"])

    # show values on bars
    for i, v in enumerate(df["count"]):
        plt.text(v + 2, i, str(v), va='center')

    plt.xlabel("Count")
    plt.ylabel(label.capitalize())
    plt.title(title)

    # grid
    plt.grid(axis="x", linestyle="--", alpha=0.5)

    # clean borders
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(output, dpi=300)
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

print("✅ All charts generated successfully!")
