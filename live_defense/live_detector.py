#!/usr/bin/env python3

import json
import os
import sys
import time
from collections import defaultdict, deque

# Make project root importable
PROJECT_ROOT = "/home/cowrie/cowrie-analysis"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from detect_advanced_patterns import (
    has_ssh_backdoor_pattern,
    has_dropper_oneliner_pattern,
)

LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

# ============================================================
# LIVE DETECTION PARAMETERS
# ============================================================

WINDOW_SECONDS = 60

FAILED_LOGIN_THRESHOLD = 10
COMMAND_THRESHOLD = 10
DIRECT_TCPIP_THRESHOLD = 5
DOWNLOAD_THRESHOLD = 2
BURST_THRESHOLD = 10


# ============================================================
# PER-IP EVENT STATE
# ============================================================

state = defaultdict(
    lambda: {
        "events": deque()
    }
)


# ============================================================
# WINDOW MANAGEMENT
# ============================================================

def cleanup_old_events(ip, now):
    events = state[ip]["events"]
    cutoff = now - WINDOW_SECONDS

    while events and events[0]["time"] < cutoff:
        events.popleft()


def get_features(ip, now):
    """
    Calculate ALL features only from events inside
    the current sliding time window.
    """

    cleanup_old_events(ip, now)

    events = state[ip]["events"]

    features = {
        "failed_login": 0,
        "success_login": 0,
        "commands": 0,
        "downloads": 0,
        "uploads": 0,
        "direct_tcpip": 0,
        "backdoor": 0,
        "dropper": 0,
    }

    for item in events:
        eventid = item["eventid"]

        if eventid == "cowrie.login.failed":
            features["failed_login"] += 1

        elif eventid == "cowrie.login.success":
            features["success_login"] += 1

        elif eventid == "cowrie.command.input":
            features["commands"] += 1

            if item.get("backdoor"):
                features["backdoor"] += 1

            if item.get("dropper"):
                features["dropper"] += 1

        elif eventid == "cowrie.session.file_download":
            features["downloads"] += 1

        elif eventid == "cowrie.session.file_upload":
            features["uploads"] += 1

        elif eventid == "cowrie.direct-tcpip.request":
            features["direct_tcpip"] += 1

    return features


# ============================================================
# DECISION ENGINE
# ============================================================

def decision(ip, now):

    features = get_features(ip, now)

    burst = len(state[ip]["events"])

    # --------------------------------------------------------
    # CRITICAL ATTACK PATTERNS
    # --------------------------------------------------------

    if features["backdoor"] > 0:
        return (
            "ACL_BLOCK_CANDIDATE",
            "SSH_BACKDOOR_PATTERN",
            features,
            burst,
        )

    if features["dropper"] > 0:
        return (
            "ACL_BLOCK_CANDIDATE",
            "DROPPER_PATTERN",
            features,
            burst,
        )

    # --------------------------------------------------------
    # DIRECT TCP/IP ABUSE
    # --------------------------------------------------------

    if features["direct_tcpip"] >= DIRECT_TCPIP_THRESHOLD:
        return (
            "ACL_BLOCK_CANDIDATE",
            "DIRECT_TCPIP_ABUSE",
            features,
            burst,
        )

    # --------------------------------------------------------
    # BRUTE FORCE
    # --------------------------------------------------------

    if features["failed_login"] >= FAILED_LOGIN_THRESHOLD:
        return (
            "ACL_BLOCK_CANDIDATE",
            "BRUTE_FORCE",
            features,
            burst,
        )

    # --------------------------------------------------------
    # COMMAND BURST
    # --------------------------------------------------------

    if (
        features["commands"] >= COMMAND_THRESHOLD
        and burst >= BURST_THRESHOLD
    ):
        return (
            "ACL_BLOCK_CANDIDATE",
            "COMMAND_BURST",
            features,
            burst,
        )

    # --------------------------------------------------------
    # DOWNLOAD BURST
    # --------------------------------------------------------

    if (
        features["downloads"] >= DOWNLOAD_THRESHOLD
        and burst >= BURST_THRESHOLD
    ):
        return (
            "ACL_BLOCK_CANDIDATE",
            "DOWNLOAD_BURST",
            features,
            burst,
        )

    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    if burst >= BURST_THRESHOLD:
        return (
            "MONITOR",
            "EVENT_BURST",
            features,
            burst,
        )

    return (
        "NO_ACTION",
        "NORMAL",
        features,
        burst,
    )


# ============================================================
# EVENT PROCESSOR
# ============================================================

def process_event(event):

    if not isinstance(event, dict):
        return

    eventid = event.get("eventid")
    ip = event.get("src_ip")

    if not eventid or not ip:
        return

    now = time.time()

    item = {
        "time": now,
        "eventid": eventid,
    }

    # --------------------------------------------------------
    # COMMAND PATTERN DETECTION
    # --------------------------------------------------------

    if eventid == "cowrie.command.input":

        command = event.get("input", "")

        item["backdoor"] = has_ssh_backdoor_pattern(command)
        item["dropper"] = has_dropper_oneliner_pattern(command)

    # Store event
    state[ip]["events"].append(item)

    # Remove events older than 60 seconds
    cleanup_old_events(ip, now)

    # Decision
    action, reason, features, burst = decision(ip, now)

    print(
        f"[DETECT] "
        f"{eventid:<32} "
        f"IP={ip:<15} "
        f"burst={burst:<3} "
        f"failed={features['failed_login']:<3} "
        f"cmd={features['commands']:<3} "
        f"tcpip={features['direct_tcpip']:<3} "
        f"download={features['downloads']:<2} "
        f"action={action:<22} "
        f"reason={reason}",
        flush=True,
    )


# ============================================================
# FILE WATCHER
# ============================================================

class CowrieHandler(FileSystemEventHandler):

    def __init__(self):
        self.position = os.path.getsize(LOG_FILE)
        self.buffer = ""

    def process_new_lines(self):

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:

                f.seek(self.position)

                data = f.read()

                if not data:
                    return

                self.position = f.tell()

                self.buffer += data

                lines = self.buffer.split("\n")

                self.buffer = lines.pop()

                for line in lines:

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(line)

                    except json.JSONDecodeError:
                        continue

                    process_event(event)

        except FileNotFoundError:
            print(
                f"[ERROR] Log file not found: {LOG_FILE}",
                flush=True,
            )

    def on_modified(self, event):

        if event.is_directory:
            return

        if event.src_path == LOG_FILE:
            self.process_new_lines()


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 110)
    print("COWRIE LIVE DETECTION ENGINE")
    print("=" * 110)
    print(f"Watching : {LOG_FILE}")
    print(f"Window   : {WINDOW_SECONDS} seconds")
    print("Mode     : TRUE SLIDING WINDOW")
    print("Starting from current end of file.")
    print("Waiting for NEW attacks...")
    print("Press Ctrl+C to stop.")
    print("=" * 110)

    handler = CowrieHandler()

    observer = Observer()
    observer.schedule(
        handler,
        os.path.dirname(LOG_FILE),
        recursive=False,
    )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\nStopping live detector...", flush=True)

        observer.stop()

    observer.join()

    print("Live detector stopped.", flush=True)



if __name__ == "__main__":
    main()
