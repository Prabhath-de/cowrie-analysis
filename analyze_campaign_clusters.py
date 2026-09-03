"""
analyze_campaign_clusters.py -- memory-safe streaming version.

Groups sessions by shared ttylog_shasums (identical recorded TTY output
-- i.e. identical attack script/payload) to find campaigns/botnets that
span many distinct source IPs and countries but run byte-identical
sessions. Read-only, streaming (row by row), safe for low-RAM servers.
"""

import csv
from collections import defaultdict

R = "research_csv"

# ---------------- load geoip lookup (small file, safe to hold fully) ----------------
ip_country = {}
try:
    with open(f"{R}/geoip_per_ip.csv", newline="") as f:
        for r in csv.DictReader(f):
            ip_country[r["src_ip"]] = r.get("country") or "Unknown"
except FileNotFoundError:
    pass

# ---------------- stream sessions_full.csv, build shasum -> {ips, versions, countries} ----------------
shasum_ips = defaultdict(set)
shasum_sessions = defaultdict(int)
shasum_versions = defaultdict(set)

with open(f"{R}/sessions_full.csv", newline="") as f:
    reader = csv.DictReader(f)
    for i, r in enumerate(reader, 1):
        if i % 100000 == 0:
            print(f"  ...processed {i} rows so far")
        shasums = r.get("ttylog_shasums") or ""
        if not shasums:
            continue
        ip = r.get("src_ip")
        cv = r.get("client_version")
        for sh in shasums.split(";"):
            if not sh:
                continue
            shasum_sessions[sh] += 1
            if ip:
                shasum_ips[sh].add(ip)
            if cv:
                shasum_versions[sh].add(cv)

print(f"\nDistinct ttylog shasums observed: {len(shasum_sessions)}")

# only clusters spanning more than one distinct IP are "campaigns"
clusters = [
    (sh, len(ips), shasum_sessions[sh], ips, shasum_versions[sh])
    for sh, ips in shasum_ips.items()
    if len(ips) > 1
]
clusters.sort(key=lambda c: -c[1])

print(f"Shasums shared across MULTIPLE distinct IPs (campaign candidates): {len(clusters)}")
print("\nTop 15 largest campaigns by distinct-IP count:")
print("-" * 100)
for sh, n_ips, n_sessions, ips, versions in clusters[:15]:
    countries = set(ip_country.get(ip, "Unknown") for ip in ips)
    print(f"shasum={sh[:16]}...  distinct_ips={n_ips:5d}  sessions={n_sessions:5d}  "
          f"countries={len(countries):3d}  client_versions={len(versions)}")
    print(f"  countries: {', '.join(sorted(countries)[:8])}{' ...' if len(countries) > 8 else ''}")
    print(f"  sample client_versions: {', '.join(sorted(versions)[:3])}")
    print()

total_ips_in_campaigns = len(set().union(*[c[3] for c in clusters])) if clusters else 0
print(f"Total distinct IPs participating in ANY multi-IP campaign: {total_ips_in_campaigns}")

print("\nDone.")
