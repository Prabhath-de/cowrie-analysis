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

    # normalize column names (IMPORTANT FIX)
    df.columns = df.columns.str.strip().str.lower()

    # remove empty rows
    df = df.dropna()

    # take top N
    df = df.head(TOP_N)

    # reverse for horizontal chart
    df = df[::-1]

    plt.figure(figsize=(10, 6))
    plt.barh(df[label.lower()], df["count"])

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

# ---------- COUNTRIES CHART ----------
try:
    df_countries = pd.read_csv(f"{CSV_DIR}/countries.csv")

    # normalize columns
    df_countries.columns = df_countries.columns.str.strip()

    df_countries = df_countries.dropna()
    df_countries = df_countries.head(TOP_N)
    df_countries = df_countries[::-1]

    plt.figure(figsize=(10, 6))
    plt.barh(df_countries["Country"], df_countries["Count"])

    # show values
    for i, v in enumerate(df_countries["Count"]):
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
    print("❌ countries chart error:", e)


print("✅ All charts generated successfully!")
