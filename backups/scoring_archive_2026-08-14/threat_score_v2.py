#!/usr/bin/env python3

import json
import glob
import os
from collections import defaultdict

BASE_DIR = "/home/cowrie/cowrie-analysis"
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
WEIGHTS_FILE = os.path.join(BASE_DIR, "scoring", "threat_weights.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "scoring", "validation_scores.csv")


# ============================================================
# LOAD FROZEN MODEL
# ============================================================

with open(WEIGHTS_FILE, "r", encoding="utf-8") as f:
    model = json.load(f)

features_cfg = model["features"]
thresholds = model["risk_thresholds_raw"]

P75 = "p75"
P90 = "p90"
P95 = "p95"
P99 = "p99"


# ============================================================
# FEATURE SCORING
# ============================================================

def percentile_score(value, cfg):
    """
    Convert a raw feature count into 0-4 points
    using frozen calibration percentiles.
    """

    p75 = cfg["p75"]
    p90 = cfg["p90"]
    p95 = cfg["p95"]
    p99 = cfg["p99"]

    if value <= p75:
        return 0
    elif value <= p90:
        return 1
    elif value <= p95:
        return 2
    elif value <= p99:
        return 3
    else:
        return 4


def score_presence(value, cfg):
    if value == 0:
        return cfg["points"]["zero"]
    return cfg["points"]["nonzero"]


def score_file_upload(value, cfg):
    if value == 0:
        return cfg["points"]["zero"]
    elif value == 1:
        return cfg["points"]["one"]
    else:
        return cfg["points"]["two_or_more"]


def calculate_feature_scores(raw):
    scores = {}

    # Percentile features
    for name in [
        "sessions",
        "login_failed",
        "commands",
        "dropper_pattern",
        "direct_tcpip",
    ]:
        scores[name] = percentile_score(
            raw[name],
            features_cfg[name]
        )

    # Sparse presence features
    scores["command_failed_other"] = score_presence(
        raw["command_failed_other"],
        features_cfg["command_failed_other"]
    )

    scores["file_upload"] = score_file_upload(
        raw["file_upload"],
        features_cfg["file_upload"]
    )

    scores["failed_download"] = score_presence(
        raw["failed_download"],
        features_cfg["failed_download"]
    )

    return scores


# ============================================================
# RISK CLASSIFICATION
# ============================================================

def classify_risk(raw_score):
    if raw_score <= thresholds["low_max"]:
        return "LOW"

    elif raw_score <= thresholds["medium_max"]:
        return "MEDIUM"

    elif raw_score <= thresholds["high_max"]:
        return "HIGH"

    else:
        return "CRITICAL"


def calculate_final_score(raw_score):
    max_raw = model["model"]["max_raw_score"]

    return round((raw_score / max_raw) * 100)


# ============================================================
# SELECT VALIDATION FILES
# ============================================================

validation_start = model["validation_period"]["start"]

all_files = sorted(
    glob.glob(
        os.path.join(
            BACKUP_DIR,
            "cowrie_*.json"
        )
    )
)

validation_files = [
    f for f in all_files
    if os.path.basename(f).replace(
        "cowrie_", ""
    ).replace(
        ".json", ""
    ) >= validation_start
]

print("=" * 70)
print("DETERMINISTIC THREAT SCORING V2")
print("=" * 70)

print(f"Validation start : {validation_start}")
print(f"Files selected   : {len(validation_files)}")

if validation_files:
    print(
        "Date range       : "
        f"{os.path.basename(validation_files[0])} -> "
        f"{os.path.basename(validation_files[-1])}"
    )

print()


# ============================================================
# PER-IP FEATURES
# ============================================================

ip_features = defaultdict(
    lambda: {
        "sessions": 0,
        "login_failed": 0,
        "commands": 0,
        "dropper_pattern": 0,
        "direct_tcpip": 0,
        "command_failed_other": 0,
        "file_upload": 0,
        "failed_download": 0,
    }
)

# Session-level temporary information
session_has_download = set()
command_failed_events = []

total_events = 0
malformed = 0
unique_ips = set()


# ============================================================
# READ VALIDATION DATA
# ============================================================

for filepath in validation_files:

    print(
        "Processing:",
        os.path.basename(filepath)
    )

    try:
        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as fh:

            for line in fh:

                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue

                eventid = event.get("eventid")
                ip = event.get("src_ip")
                session = event.get("session")

                if not eventid or not ip:
                    continue

                total_events += 1
                unique_ips.add(ip)

                # ----------------------------------------
                # SESSION
                # ----------------------------------------

                if eventid == "cowrie.session.connect":
                    ip_features[ip]["sessions"] += 1

                # ----------------------------------------
                # FAILED LOGIN
                # ----------------------------------------

                elif eventid == "cowrie.login.failed":
                    ip_features[ip]["login_failed"] += 1

                # ----------------------------------------
                # COMMAND INPUT
                # ----------------------------------------

                elif eventid == "cowrie.command.input":
                    ip_features[ip]["commands"] += 1

                # ----------------------------------------
                # COMMAND FAILED
                # ----------------------------------------

                elif eventid == "cowrie.command.failed":

                    command_failed_events.append(
                        (ip, session)
                    )

                # ----------------------------------------
                # FILE DOWNLOAD
                # ----------------------------------------

                elif eventid == "cowrie.session.file_download":

                    ip_features[ip]["commands"] += 0

                    if session:
                        session_has_download.add(session)

                    # Separate feature
                    ip_features[ip]["dropper_pattern"] += 0

                # ----------------------------------------
                # FAILED FILE DOWNLOAD
                # ----------------------------------------

                elif eventid == "cowrie.session.file_download.failed":

                    if session:
                        session_has_download.add(session)

                    ip_features[ip]["failed_download"] += 1

                # ----------------------------------------
                # FILE UPLOAD
                # ----------------------------------------

                elif eventid == "cowrie.session.file_upload":

                    ip_features[ip]["file_upload"] += 1

                # ----------------------------------------
                # DIRECT TCP/IP
                # ----------------------------------------

                elif eventid == "cowrie.direct-tcpip.request":

                    ip_features[ip]["direct_tcpip"] += 1

    except OSError as e:

        print(
            f"WARNING: Could not read {filepath}: {e}"
        )


# ============================================================
# RESOLVE COMMAND FAILED
# ============================================================

for ip, session in command_failed_events:

    if session and session in session_has_download:

        ip_features[ip]["dropper_pattern"] += 1

    else:

        ip_features[ip]["command_failed_other"] += 1


# ============================================================
# CALCULATE SCORES
# ============================================================

results = []

for ip in sorted(unique_ips):

    raw = ip_features[ip]

    feature_scores = calculate_feature_scores(raw)

    raw_total = sum(feature_scores.values())

    final_score = calculate_final_score(raw_total)

    risk = classify_risk(raw_total)

    results.append(
        {
            "ip": ip,

            "sessions": raw["sessions"],
            "login_failed": raw["login_failed"],
            "commands": raw["commands"],
            "dropper_pattern": raw["dropper_pattern"],
            "direct_tcpip": raw["direct_tcpip"],
            "command_failed_other": raw["command_failed_other"],
            "file_upload": raw["file_upload"],
            "failed_download": raw["failed_download"],

            "sessions_score": feature_scores["sessions"],
            "login_failed_score": feature_scores["login_failed"],
            "commands_score": feature_scores["commands"],
            "dropper_pattern_score": feature_scores["dropper_pattern"],
            "direct_tcpip_score": feature_scores["direct_tcpip"],
            "command_failed_other_score":
                feature_scores["command_failed_other"],
            "file_upload_score":
                feature_scores["file_upload"],
            "failed_download_score":
                feature_scores["failed_download"],

            "raw_total": raw_total,
            "final_score": final_score,
            "risk": risk,
        }
    )


# ============================================================
# SAVE CSV
# ============================================================

import csv

if results:

    fieldnames = list(results[0].keys())

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)


# ============================================================
# SUMMARY
# ============================================================

risk_counts = defaultdict(int)

for row in results:
    risk_counts[row["risk"]] += 1


print()
print("=" * 70)
print("VALIDATION SCORING SUMMARY")
print("=" * 70)

print(
    f"Events processed : {total_events}"
)

print(
    f"Malformed lines  : {malformed}"
)

print(
    f"Unique IPs       : {len(unique_ips)}"
)

print()

for risk in [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]:

    print(
        f"{risk:8s}: "
        f"{risk_counts[risk]}"
    )

print()

print(
    f"Output: {OUTPUT_FILE}"
)

print("=" * 70)
