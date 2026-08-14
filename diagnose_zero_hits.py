"""
diagnose_zero_hits.py

Answers exactly one question: why are persistence_backdoor_hits and
dropper_execution_hits zero across all 3,866 IPs, when we already confirmed
the raw commands exist in the honeypot logs?

Checks, in order:
  1. Does research_csv/all_logs_full.csv even contain these substrings,
     intact, anywhere in its "command" column?
  2. If yes -- which IPs do they belong to, and are those IPs present in
     scoring/post_auth_combined_v1.csv (the file that defines which 3,866
     IPs get scored at all)?
  3. Sanity-check the actual column names, in case "command"/"src_ip"
     aren't exactly what both scripts assume.

Run this from /home/cowrie/cowrie-analysis. Paste the full output back --
don't summarize it, the exact repr() of a matched command matters (that's
what would reveal truncation/mangling if that's the issue).
"""

import csv

LOGFILE = "research_csv/all_logs_full.csv"
V1FILE = "scoring/post_auth_combined_v1.csv"

print("=" * 70)
print("STEP 1: raw substring presence in all_logs_full.csv")
print("=" * 70)

matches = []
total_rows = 0
with open(LOGFILE, newline="", errors="ignore") as fh:
    reader = csv.DictReader(fh)
    fieldnames = reader.fieldnames
    for row in reader:
        total_rows += 1
        cmd = row.get("command", "") or ""
        if "authorized_keys" in cmd or "chattr" in cmd or "ssh-rsa" in cmd or "ssh-ed25519" in cmd:
            matches.append((row.get("src_ip"), cmd))

print(f"Column names found: {fieldnames}")
print(f"Total rows: {total_rows}")
print(f"Rows matching authorized_keys/chattr/ssh-rsa/ssh-ed25519: {len(matches)}")
print()

if not matches:
    print("!! ZERO substring matches in the file itself.")
    print("!! This means the derived CSV does not contain these commands at")
    print("!! all -- either the upstream parser that builds all_logs_full.csv")
    print("!! filters/truncates them, or this file covers a different date")
    print("!! range than the raw cowrie.json scan that originally found them.")
else:
    print("Sample matches (up to 10), exact repr() to catch truncation/mangling:")
    for ip, cmd in matches[:10]:
        print(f"  src_ip = {ip!r}")
        print(f"  command (repr) = {cmd!r}")
        print(f"  command length = {len(cmd)} chars")
        print()

print("=" * 70)
print("STEP 2: are the matched IPs inside post_auth_combined_v1.csv?")
print("=" * 70)

v1_ips = set()
with open(V1FILE, newline="") as f:
    for row in csv.DictReader(f):
        v1_ips.add(row["ip"])

print(f"Total distinct IPs in post_auth_combined_v1.csv: {len(v1_ips)}")

if matches:
    matched_ips = set(ip for ip, _ in matches)
    present = matched_ips & v1_ips
    missing = matched_ips - v1_ips
    print(f"Distinct IPs with matching commands: {len(matched_ips)}")
    print(f"  -> present in post_auth_combined_v1.csv: {len(present)}")
    print(f"  -> MISSING from post_auth_combined_v1.csv: {len(missing)}")
    if present:
        print(f"  Present IPs (should have gotten nonzero hits!): {sorted(present)[:20]}")
    if missing:
        print(f"  Missing IPs (never scored at all, this explains zero hits for them): {sorted(missing)[:20]}")

print()
print("=" * 70)
print("STEP 3: if IPs ARE present but still show 0 -- test the regex directly")
print("=" * 70)

if matches:
    import sys
    sys.path.insert(0, ".")
    try:
        from detect_advanced_patterns import has_ssh_backdoor_pattern, has_dropper_oneliner_pattern
        for ip, cmd in matches[:5]:
            b = has_ssh_backdoor_pattern(cmd)
            d = has_dropper_oneliner_pattern(cmd)
            print(f"  ip={ip}  backdoor_detected={b}  dropper_detected={d}")
            if not b and not d:
                print(f"    !! regex did NOT fire on this exact stored string -- compare against")
                print(f"    !! the repr() above for hidden characters, encoding issues, etc.")
    except ImportError as e:
        print(f"Could not import detect_advanced_patterns.py: {e}")
        print("Make sure it's in the same directory as this script.")
