"""
analyze_session_attributes.py

Reads the Track-A outputs (sessions_full.csv, client_fingerprints.csv,
file_transfers_full.csv, geoip_per_ip.csv) and prints a compact summary
report mapping the new attributes to the categories the supervisor asked
for: IP, timing, location, frequency, tools usage. Read-only -- does not
touch scoring/ or research_csv/all_logs_full.csv.
"""

import csv
from collections import Counter

R = "research_csv"

def pct(n, d):
    return f"{100*n/d:.1f}%" if d else "0%"

print("=" * 70)
print("SESSION-LEVEL ATTRIBUTE SUMMARY (Track A)")
print("=" * 70)

# ---------------- sessions_full.csv ----------------
with open(f"{R}/sessions_full.csv", newline="") as f:
    rows = list(csv.DictReader(f))

n = len(rows)
print(f"\nTotal sessions               : {n}")

durations = [float(r["duration_sec"]) for r in rows if r["duration_sec"]]
if durations:
    durations.sort()
    print(f"Sessions with valid duration : {len(durations)} ({pct(len(durations), n)})")
    print(f"  mean duration              : {sum(durations)/len(durations):.2f}s")
    print(f"  median duration            : {durations[len(durations)//2]:.2f}s")
    print(f"  max duration               : {max(durations):.1f}s")

pty = sum(1 for r in rows if r["has_pty"] == "True")
print(f"\nSessions with PTY (interactive signal): {pty} ({pct(pty, n)})")
print(f"Sessions fully automated/scripted     : {n-pty} ({pct(n-pty, n)})")

login_ok = sum(1 for r in rows if r["login_success"] == "True")
print(f"\nSessions with successful login : {login_ok} ({pct(login_ok, n)})")

dtcp = sum(1 for r in rows if int(r["direct_tcpip_count"] or 0) > 0)
print(f"Sessions attempting pivot/proxy (direct-tcpip): {dtcp} ({pct(dtcp, n)})")

dup = sum(1 for r in rows if r["ttylog_any_duplicate"] == "True")
print(f"Sessions matching a previously-seen TTY recording (campaign signal): {dup} ({pct(dup, n)})")

arch_counter = Counter(r["arch"] for r in rows if r["arch"])
print(f"\nDistinct reported architectures: {len(arch_counter)}")
for a, c in arch_counter.most_common(5):
    print(f"  {a}: {c}")

# ---------------- client_fingerprints.csv ----------------
with open(f"{R}/client_fingerprints.csv", newline="") as f:
    fps = list(csv.DictReader(f))
print(f"\nDistinct HASSH tool fingerprints: {len(fps)}")
print("Top 5 by session count:")
for row in sorted(fps, key=lambda r: -int(r["session_count"]))[:5]:
    print(f"  {row['hassh'][:12]}...  sessions={row['session_count']:>7}  sample_client={row['sample_client_version']}")

cv_counter = Counter(r["client_version"] for r in rows if r["client_version"])
print(f"\nDistinct SSH client version banners: {len(cv_counter)}")
print("Top 5:")
for v, c in cv_counter.most_common(5):
    print(f"  {v}: {c}")

# ---------------- file_transfers_full.csv ----------------
with open(f"{R}/file_transfers_full.csv", newline="") as f:
    transfers = list(csv.DictReader(f))
downloads = [r for r in transfers if r["event"] == "cowrie.session.file_download"]
uniq_hashes = set(r["shasum"] for r in downloads if r["shasum"])
with_url = [r for r in downloads if r["url"]]
print(f"\nTotal file download events   : {len(downloads)}")
print(f"Distinct malware sample hashes: {len(uniq_hashes)}")
print(f"Downloads with external URL   : {len(with_url)} ({pct(len(with_url), len(downloads))})")

# ---------------- geoip_per_ip.csv ----------------
try:
    with open(f"{R}/geoip_per_ip.csv", newline="") as f:
        geo = list(csv.DictReader(f))
    country_counter = Counter(r["country"] for r in geo if r["country"] and r["country"] != "Unknown")
    print(f"\nDistinct source countries (per unique IP): {len(country_counter)}")
    print("Top 10:")
    for c, cnt in country_counter.most_common(10):
        print(f"  {c}: {cnt}")
except FileNotFoundError:
    print("\ngeoip_per_ip.csv not found -- skipping location breakdown")

print("\n" + "=" * 70)
print("Done.")
