import json
import time
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
LOG_DIR = "/home/cowrie/cowrie/var/log/cowrie"


class CowrieHandler(FileSystemEventHandler):

    def __init__(self):
        self.position = 0
        self.buffer = ""

    def start_position(self):
        self.position = os.path.getsize(LOG_FILE)

    def process_new_lines(self):

        try:
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                f.seek(self.position)

                data = f.read()

                if not data:
                    return

                self.position = f.tell()

                # Add new data to incomplete-line buffer
                self.buffer += data

                # Only process complete lines
                lines = self.buffer.split("\n")

                # Last element may be incomplete
                self.buffer = lines.pop()

                for line in lines:

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(line)

                    except json.JSONDecodeError:
                        # Do NOT discard incomplete/corrupt line silently
                        print(
                            "[WATCHER] Invalid JSON line skipped",
                            flush=True
                        )
                        continue

                    if not isinstance(event, dict):
                        print(
                            "[WATCHER] Non-object JSON skipped",
                            flush=True
                        )
                        continue

                    eventid = event.get("eventid", "-")
                    src_ip = event.get("src_ip", "-")
                    session = event.get("session", "-")
                    timestamp = event.get("timestamp", "-")

                    print(
                        f"[LIVE] "
                        f"{timestamp} | "
                        f"{eventid} | "
                        f"{src_ip} | "
                        f"{session}",
                        flush=True
                    )

        except FileNotFoundError:
            print(
                "[WATCHER] Cowrie log not found",
                flush=True
            )

        except Exception as e:
            print(
                f"[WATCHER ERROR] {type(e).__name__}: {e}",
                flush=True
            )

    def on_modified(self, event):

        if event.is_directory:
            return

        if os.path.abspath(event.src_path) == os.path.abspath(LOG_FILE):
            self.process_new_lines()


handler = CowrieHandler()

handler.start_position()

observer = Observer()

observer.schedule(
    handler,
    LOG_DIR,
    recursive=False
)

observer.start()

print("=" * 80)
print("COWRIE LIVE WATCHER TEST")
print("=" * 80)
print(f"Watching: {LOG_FILE}")
print("Starting from current end of file.")
print("Waiting for NEW Cowrie events...")
print("Press Ctrl+C to stop.")
print("=" * 80)

try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping watcher...")

finally:

    observer.stop()
    observer.join()

print("Watcher stopped.")
