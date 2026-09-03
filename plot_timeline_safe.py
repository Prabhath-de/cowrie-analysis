"""
plot_timeline_safe.py -- memory-safe replacement for research_analyze.py's
plot_timeline(). Streams all_logs_full.csv row by row (never loads it
fully into a pandas DataFrame) and keeps only a small per-day Counter,
then plots that tiny aggregate. Safe on low-RAM servers.
"""

import csv
from collections import Counter
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV_DIR = "research_csv"
IMG_DIR = "research_images"

daily_counts = Counter()

with open(f"{CSV_DIR}/all_logs_full.csv", newline="") as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader, 1):
        if i % 200000 == 0:
            print(f"  ...processed {i} rows so far")
        ts = row.get("timestamp")
        if ts and len(ts) >= 10:
            date = ts[:10]  # "YYYY-MM-DD" prefix, no datetime parsing needed
            daily_counts[date] += 1

print(f"Distinct dates: {len(daily_counts)}")

dates = sorted(daily_counts.keys())
counts = [daily_counts[d] for d in dates]

plt.figure(figsize=(14, 6))
plt.plot(dates, counts, marker='o')
plt.xlabel("Date")
plt.ylabel("Number of Events")
plt.title("Daily Attack Activity Over Research Period")
plt.grid(True, linestyle="--", alpha=0.5)

# thin out x-axis labels so it stays readable with 150+ dates
step = max(1, len(dates) // 20)
plt.xticks(range(0, len(dates), step), [dates[i] for i in range(0, len(dates), step)], rotation=45)

plt.tight_layout()
plt.savefig(f"{IMG_DIR}/timeline_full.png", dpi=300)
plt.close()

print(f"Created: {IMG_DIR}/timeline_full.png")
print("Done.")
