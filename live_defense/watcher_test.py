import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
LOG_DIR = "/home/cowrie/cowrie/var/log/cowrie"


class CowrieHandler(FileSystemEventHandler):

    def __init__(self):
        self.position = 0

    def start_position(self):
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            self.position = f.tell()

    def process_new_lines(self):
        try:
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                f.seek(self.position)

                while True:
                    line = f.readline()

                    if not line:
                        break

                    self.position = f.tell()

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    print(
                        f"[LIVE] "
                        f"{event.get('timestamp')} | "
                        f"{event.get('eventid')} | "
                        f"{event.get('src_ip')} | "
                        f"{event.get('session')}",
                        flush=True
                    )

        except FileNotFoundError:
            pass

    def on_modified(self, event):
        if event.src_path == LOG_FILE:
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
print("Waiting for new Cowrie events...")
print("Press Ctrl+C to stop.")
print("=" * 80)

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    observer.stop()

observer.join()
