"""
research_parse_sessions.py -- SESSION-level attribute extraction.

Companion to research_parse_logs.py. That script keeps only 3 event types
(cowrie.command.input, cowrie.login.failed, cowrie.login.success) and has
no `session` column, so per-session timing (duration, dwell time),
tool/client fingerprinting, and file-transfer/pivot attributes are
impossible to derive from its output. This script re-reads the SAME raw
backup files and extracts those additional attributes without touching
research_parse_logs.py, all_logs_full.csv, or anything under scoring/ --
Track A only (dataset characterization), no scoring/calibration impact.

Memory design: same streaming philosophy as research_parse_logs.py. We
DO need to hold state per session between cowrie.session.connect and
cowrie.session.closed, so a session dict is kept in memory -- but only
for sessions that are currently OPEN. Each session is flushed to CSV and
deleted from memory the moment its cowrie.session.closed / cowrie.log.closed
arrives. Memory therefore scales with concurrent open sessions, not with
total dataset size.

Outputs:
    research_csv/sessions_full.csv          -- one row per session (lean --
                                                only the "hassh" hash, not
                                                the full algorithm strings)
    research_csv/client_fingerprints.csv    -- one row per DISTINCT hassh,
                                                with the full algorithm
                                                strings. Join on "hassh".
                                                (Only ~300 distinct values
                                                vs 400k+ sessions -- storing
                                                the full strings per-session
                                                inflated sessions_full.csv
                                                to 620MB for zero extra
                                                information; this join
                                                table is <1MB.)
    research_csv/file_transfers_full.csv    -- one row per download/upload event
    research_csv/geoip_per_ip.csv           -- one row per unique src_ip

Any session still open at end-of-processing (truncated log, ongoing
connection) is flushed anyway with duration=None and incomplete=True,
rather than silently dropped.
"""

import json
import os
import glob
import csv
from collections import defaultdict

BACKUP_DIR = "/home/cowrie/cowrie-analysis/backups"
CURRENT_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_DIR = "research_csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

SESSION_FIELDS = [
    "session", "src_ip", "src_port", "dst_ip", "dst_port",
    "connect_ts", "close_ts", "duration_sec", "incomplete",
    "client_version", "hassh",              # join client_fingerprints.csv on hassh for full algo strings
    "arch", "has_pty", "term_width", "term_height",
    "login_attempts", "login_success", "distinct_usernames_tried",
    "distinct_passwords_tried",
    "commands_count", "command_failed_count",
    "file_download_count", "file_upload_count", "file_download_failed_count",
    "direct_tcpip_count", "direct_tcpip_unique_targets",
    "ttylog_fragment_count", "ttylog_active_duration_sec", "ttylog_total_size",
    "ttylog_shasums", "ttylog_any_duplicate",
    "source_file",
]

FINGERPRINT_FIELDS = [
    "hassh", "hasshAlgorithms", "kexAlgs", "keyAlgs",
    "encCS", "macCS", "compCS", "langCS",
    "sample_client_version", "session_count",
]

FILE_TRANSFER_FIELDS = [
    "session", "src_ip", "event", "timestamp",
    "url", "filename", "outfile", "destfile", "shasum",
]

# ---------------------------------------------------------
# Per-session open state
# ---------------------------------------------------------

open_sessions = {}   # session_id -> dict of accumulated fields
ip_seen = set()
fingerprints = {}    # hassh -> dict of algo strings + session_count (deduped)

total_events = 0
sessions_written = 0
file_transfer_rows = 0


def new_session_state(sess_id, ip, port, dst_ip, dst_port, ts, source_file):
    return {
        "session": sess_id,
        "src_ip": ip,
        "src_port": port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "connect_ts": ts,
        "close_ts": None,
        "duration_sec": None,
        "incomplete": True,
        "client_version": None,
        "hassh": None,
        "arch": None,
        "has_pty": False,
        "term_width": None,
        "term_height": None,
        "login_attempts": 0,
        "login_success": False,
        "usernames_tried": set(),
        "passwords_tried": set(),
        "commands_count": 0,
        "command_failed_count": 0,
        "file_download_count": 0,
        "file_upload_count": 0,
        "file_download_failed_count": 0,
        "direct_tcpip_count": 0,
        "direct_tcpip_targets": set(),
        "ttylog_fragment_count": 0,
        "ttylog_active_duration_sec": 0.0,
        "ttylog_total_size": 0,
        "ttylog_shasums": set(),
        "ttylog_any_duplicate": False,
        "source_file": source_file,
    }


def flush_session(sess_id, session_writer):
    global sessions_written
    st = open_sessions.pop(sess_id, None)
    if st is None:
        return
    row = {k: st[k] for k in SESSION_FIELDS if k in st}
    row["login_attempts"] = st["login_attempts"]
    row["login_success"] = st["login_success"]
    row["distinct_usernames_tried"] = len(st["usernames_tried"])
    row["distinct_passwords_tried"] = len(st["passwords_tried"])
    row["direct_tcpip_unique_targets"] = len(st["direct_tcpip_targets"])
    row["ttylog_shasums"] = ";".join(sorted(st["ttylog_shasums"]))
    for k in SESSION_FIELDS:
        if k not in row:
            row[k] = st.get(k)
    session_writer.writerow(row)
    sessions_written += 1


def process_log_file(log_file, session_writer, transfer_writer):
    global total_events, file_transfer_rows

    if not os.path.exists(log_file):
        print(f"WARNING File not found: {log_file}")
        return

    print(f"Reading: {log_file}")
    source_file = os.path.basename(log_file)
    rows_this_file = 0

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue

            eventid = d.get("eventid")
            ts = d.get("timestamp")
            ip = d.get("src_ip")
            sess = d.get("session")

            if not eventid or not ts:
                continue

            total_events += 1
            if ip:
                ip_seen.add(ip)

            # ---------------- SESSION CONNECT ----------------
            if eventid == "cowrie.session.connect":
                open_sessions[sess] = new_session_state(
                    sess, ip, d.get("src_port"),
                    d.get("dst_ip"), d.get("dst_port"),
                    ts, source_file
                )
                continue

            st = open_sessions.get(sess)
            if st is None:
                # event for a session we never saw connect() for
                # (log rotated mid-session at a file boundary) -- create
                # a minimal placeholder rather than silently dropping it
                st = new_session_state(sess, ip, None, None, None, None, source_file)
                st["incomplete"] = True
                open_sessions[sess] = st

            # ---------------- CLIENT VERSION / KEX ----------------
            if eventid == "cowrie.client.version":
                st["client_version"] = d.get("version")

            elif eventid == "cowrie.client.kex":
                h = d.get("hassh")
                st["hassh"] = h
                if h and h not in fingerprints:
                    fingerprints[h] = {
                        "hassh": h,
                        "hasshAlgorithms": d.get("hasshAlgorithms"),
                        "kexAlgs": ";".join(d.get("kexAlgs", []) or []),
                        "keyAlgs": ";".join(d.get("keyAlgs", []) or []),
                        "encCS": ";".join(d.get("encCS", []) or []),
                        "macCS": ";".join(d.get("macCS", []) or []),
                        "compCS": ";".join(d.get("compCS", []) or []),
                        "langCS": ";".join(d.get("langCS", []) or []),
                        "sample_client_version": st.get("client_version"),
                        "session_count": 0,
                    }
                if h:
                    fingerprints[h]["session_count"] += 1
                    if not fingerprints[h]["sample_client_version"] and st.get("client_version"):
                        fingerprints[h]["sample_client_version"] = st.get("client_version")

            elif eventid == "cowrie.session.params":
                st["arch"] = d.get("arch")

            elif eventid == "cowrie.client.size":
                st["has_pty"] = True
                st["term_width"] = d.get("width")
                st["term_height"] = d.get("height")

            # ---------------- LOGIN ----------------
            elif eventid in ("cowrie.login.failed", "cowrie.login.success"):
                st["login_attempts"] += 1
                if d.get("username"):
                    st["usernames_tried"].add(d.get("username"))
                if d.get("password"):
                    st["passwords_tried"].add(d.get("password"))
                if eventid == "cowrie.login.success":
                    st["login_success"] = True

            # ---------------- COMMANDS ----------------
            elif eventid == "cowrie.command.input":
                st["commands_count"] += 1

            elif eventid == "cowrie.command.failed":
                st["command_failed_count"] += 1

            # ---------------- FILE TRANSFERS ----------------
            elif eventid == "cowrie.session.file_download":
                st["file_download_count"] += 1
                transfer_writer.writerow({
                    "session": sess, "src_ip": ip, "event": eventid, "timestamp": ts,
                    "url": d.get("url"), "filename": d.get("destfile"),
                    "outfile": d.get("outfile"), "destfile": d.get("destfile"),
                    "shasum": d.get("shasum"),
                })
                file_transfer_rows += 1

            elif eventid == "cowrie.session.file_download.failed":
                st["file_download_failed_count"] += 1
                transfer_writer.writerow({
                    "session": sess, "src_ip": ip, "event": eventid, "timestamp": ts,
                    "url": d.get("url"), "filename": None,
                    "outfile": None, "destfile": None, "shasum": None,
                })
                file_transfer_rows += 1

            elif eventid == "cowrie.session.file_upload":
                st["file_upload_count"] += 1
                transfer_writer.writerow({
                    "session": sess, "src_ip": ip, "event": eventid, "timestamp": ts,
                    "url": None, "filename": d.get("filename"),
                    "outfile": d.get("outfile"), "destfile": None,
                    "shasum": d.get("shasum"),
                })
                file_transfer_rows += 1

            # ---------------- DIRECT-TCPIP (pivot/lateral movement) ----------------
            elif eventid == "cowrie.direct-tcpip.request":
                st["direct_tcpip_count"] += 1
                tgt_ip = d.get("dst_ip")
                tgt_port = d.get("dst_port")
                if tgt_ip is not None:
                    st["direct_tcpip_targets"].add(f"{tgt_ip}:{tgt_port}")

            # ---------------- LOG CLOSED (TTY recording, shell sessions only) ----
            elif eventid == "cowrie.log.closed":
                st["ttylog_fragment_count"] += 1
                dur = d.get("duration")
                if dur:
                    try:
                        st["ttylog_active_duration_sec"] += float(dur)
                    except (TypeError, ValueError):
                        pass
                sz = d.get("size")
                if sz:
                    try:
                        st["ttylog_total_size"] += int(sz)
                    except (TypeError, ValueError):
                        pass
                sh = d.get("shasum")
                if sh:
                    st["ttylog_shasums"].add(sh)
                if d.get("duplicate"):
                    st["ttylog_any_duplicate"] = True

            # ---------------- SESSION CLOSED (fires for ~every session) ----
            elif eventid == "cowrie.session.closed":
                st["close_ts"] = ts
                st["duration_sec"] = d.get("duration")  # authoritative, full-session
                st["incomplete"] = False
                flush_session(sess, session_writer)
                rows_this_file += 1
                continue

    print(f"  -> {rows_this_file} sessions flushed from this file")


# =========================================================
# MAIN
# =========================================================

sessions_path = f"{OUTPUT_DIR}/sessions_full.csv"
transfers_path = f"{OUTPUT_DIR}/file_transfers_full.csv"
geoip_path = f"{OUTPUT_DIR}/geoip_per_ip.csv"

with open(sessions_path, "w", newline="", encoding="utf-8") as sf, \
     open(transfers_path, "w", newline="", encoding="utf-8") as tf:

    session_writer = csv.DictWriter(sf, fieldnames=SESSION_FIELDS)
    session_writer.writeheader()
    transfer_writer = csv.DictWriter(tf, fieldnames=FILE_TRANSFER_FIELDS)
    transfer_writer.writeheader()

    backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "cowrie_*.json")))
    print(f"Found {len(backup_files)} backup files")

    for bf in backup_files:
        process_log_file(bf, session_writer, transfer_writer)

    if os.path.exists(CURRENT_LOG):
        process_log_file(CURRENT_LOG, session_writer, transfer_writer)
    else:
        print(f"NOTE: current live log not found at {CURRENT_LOG} (fine if running off-server)")

    for sess_id in list(open_sessions.keys()):
        flush_session(sess_id, session_writer)

fingerprints_path = f"{OUTPUT_DIR}/client_fingerprints.csv"
with open(fingerprints_path, "w", newline="", encoding="utf-8") as ff:
    fw = csv.DictWriter(ff, fieldnames=FINGERPRINT_FIELDS)
    fw.writeheader()
    for h, row in sorted(fingerprints.items(), key=lambda kv: -kv[1]["session_count"]):
        fw.writerow(row)

print(f"\nTotal events scanned : {total_events}")
print(f"Sessions written      : {sessions_written}")
print(f"File transfer rows    : {file_transfer_rows}")
print(f"Unique src_ips seen   : {len(ip_seen)}")
print(f"Distinct HASSH fingerprints: {len(fingerprints)}")
print(f"Created: {fingerprints_path}")

try:
    import geoip2.database
    reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-City.mmdb")

    with open(geoip_path, "w", newline="", encoding="utf-8") as gf:
        w = csv.writer(gf)
        w.writerow(["src_ip", "country", "city", "latitude", "longitude"])
        for ip in sorted(ip_seen):
            try:
                resp = reader.city(ip)
                w.writerow([
                    ip,
                    resp.country.name,
                    resp.city.name,
                    resp.location.latitude,
                    resp.location.longitude,
                ])
            except Exception:
                w.writerow([ip, "Unknown", None, None, None])
    print(f"Created: {geoip_path}")
except Exception as e:
    print("GeoIP not available/working:", e)

print("\nDone. Track A extraction complete -- no existing scoring/calibration files touched.")
