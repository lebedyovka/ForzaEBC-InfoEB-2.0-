# quarantine.py - карантин вредоносных процессов (Linux)

import os
import time
import signal
from datetime import datetime

dir = "quarantine"
logs = "logs/incidents.log"

os.makedirs(dir, exist_ok=True)
os.makedirs("logs", exist_ok=True)


def log_incident(text):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(logs, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {text}\n")


def kill_process(pid):

    try:
        os.kill(int(pid), signal.SIGKILL)
        return True
    except Exception:
        return False


def quarantine_process(name, pid, reason):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    record = {
        "process": name,
        "pid": pid,
        "reason": reason,
        "time": timestamp
    }

    filename = f"{name}_{pid}_{timestamp}.txt"
    path = os.path.join(dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        for k, v in record.items():
            f.write(f"{k}: {v}\n")

    log_incident(f"QUARANTINE {name} PID={pid} REASON={reason}")

    killed = kill_process(pid)

    print()
    print("[QUARANTINE]")
    print(f"    Process : {name}")
    print(f"    PID     : {pid}")
    print(f"    Reason  : {reason}")
    print(f"    Record  : {path}")

    if killed:
        print("    Action  : process terminated")
    else:
        print("    Action  : process termination failed")

    print()
    time.sleep(1)