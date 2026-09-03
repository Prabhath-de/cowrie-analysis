"""
analyze_session_attributes_v2.py -- memory-safe streaming version.

Same output as analyze_session_attributes.py but never holds the full
sessions_full.csv in memory at once -- iterates row by row and keeps
only small running counters/lists, matching the streaming approach
already used in research_parse_logs.py on this server.
"""

import csv
from collections import Counter

R = "research_csv"

def pct(n, d):
    return f"{100*n/d:.1f}%" if d else "0%"

print("=" * 70)
print("SESSION-LEVEL ATTRIBUTE SUMMARY (Track A) -- streaming")
print("=" * 70)

n = 0
duration_count = 0
duration_sum = 0.0
duration_max = 0.0
pty = 0
login_ok = 0
dtcp = 0
dup = 0
arch_counter = Counter()
cv_counter = Counter()
hassh_session_counter = Counter()   # hassh -> session count, derived here (cheap)

with open(f"{R}/sessions_full.csv", newline="") as f:
    reader = csv.DictReader(f)
    for i, r in enumerate(reader, 1):
        n += 1
        if i % 50000 == 0:
            print(f"  ...processed {i} rows so far")

        d = r.get("duration_sec")
        if d:
            try:
                dv = float(d)
                duration_count += 1
                duration_sum += dv
                if dv > duration_max:
                    duration_max = dv
            except ValueError:
                pass

        if r.get("has_pty") == "True":
            pty += 1
        if r.get("login_success") == "True":
            login_ok += 1
        try:
            if int(r.get("direct_tcpip_count") or 0) > 0:
                dtcp += 1
        except ValueError:
            pass
        if r.get("ttylog_any_duplicate") == "True":
            dup += 1
        if r.get("arch"):
            arch_counter[r["arch"]] += 1
        if r.get("client_version"):
            cv_counter[r["client_version"]] += 1
        if r.get("hassh"):
            hassh_session_counter[r["hassh"]] += 1

print(f"\nTotal sessions               : {n}")
if duration_count:
    print(f"Sessions with valid duration : {duration_count} ({pct(duration_count, n)})")
    print(f"  mean duration              : {duration_sum/duration_count:.2f}s")
    print(f"  max duration               : {duration_max:.1f}s")

print(f"\nSessions with PTY (interactive signal): {pty} ({pct(pty, n)})")
print(f"Sessions fully automated/scripted     : {n-pty} ({pct(n-pty, n)})")
print(f"\nSessions with successful login : {login_ok} ({pct(login_ok, n)})")
print(f"Sessions attempting pivot/proxy (direct-tcpip): {dtcp} ({pct(dtcp, n)})")
print(f"Sessions matching a previously-seen TTY recording (campaign signal): {dup} ({pct(dup, n)})")

print(f"\nDistinct reported architectures: {len(arch_counter)}")
for a, c in arch_counter.most_common(5):
    print(f"  {a}: {c}")

print(f"\nDistinct HASSH tool fingerprints (from sessions): {len(hassh_session_counter)}")
print("Top 5 by session count:")
for h, c in hassh_session_counter.most_common(5):
    print(f"  {h[:12]}...  sessions={c}")

print(f"\nDistinct SSH client version banners: {len(cv_counter)}")
print("Top 5:")
for v, c in cv_counter.most_common(5):
    print(f"  {v}: {c}")

# ---------------- file_transfers_full.csv (small, safe to stream too) ----------------
dl_count = 0
uniq_hashes = set()
with_url = 0
with open(f"{R}/file_transfers_full.csv", newline="") as f:
    for r in csv.DictReader(f):
        if r.get("event") == "cowrie.session.file_download":
            dl_count += 1
            if r.get("shasum"):
                uniq_hashes.add(r["shasum"])
            if r.get("url"):
                with_url += 1

print(f"\nTotal file download events    : {dl_count}")
print(f"Distinct malware sample hashes: {len(uniq_hashes)}")
print(f"Downloads with external URL   : {with_url} ({pct(with_url, dl_count)})")

# ---------------- geoip_per_ip.csv (small) ----------------
try:
    country_counter = Counter()
    with open(f"{R}/geoip_per_ip.csv", newline="") as f:
        for r in csv.DictReader(f):
            c = r.get("country")
            if c and c != "Unknown":
                country_counter[c] += 1
    print(f"\nDistinct source countries (per unique IP): {len(country_counter)}")
    print("Top 10:")
    for c, cnt in country_counter.most_common(10):
        print(f"  {c}: {cnt}")
except FileNotFoundError:
    print("\ngeoip_per_ip.csv not found -- skipping location breakdown")

print("\n" + "=" * 70)
print("Done.")
