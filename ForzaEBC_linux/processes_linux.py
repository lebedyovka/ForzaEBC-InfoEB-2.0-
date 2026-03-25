import re
import time
from colorama import Fore, Style

from run_vol import run_volatility
from quarantine import quarantine_process


SYSTEM_PROCESSES = [
    "systemd",
    "init",
    "kthreadd",
    "rcu_sched",
    "kworker",
    "migration"
]

SUSPICIOUS_DIRS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp"
]


def run_cmd(dump, plugin):

    print(Fore.CYAN + f"> vol.py -f {dump} {plugin}")
    time.sleep(1)

    return run_volatility(dump, plugin)


def parse_pslist(output):

    processes = []
    lines = output.splitlines()

    for line in lines:

        cols = re.split(r"\s{2,}", line.strip())

        if len(cols) < 4:
            continue

        name = cols[1]
        pid = cols[2]
        ppid = cols[3]

        processes.append({
            "name": name,
            "pid": pid,
            "ppid": ppid
        })

    return processes


def analyze(dump):
    print()
    print(Fore.YELLOW + Style.BRIGHT + "[MODULE] Анализ процессов (Linux)\n")

    pslist_output = run_cmd(dump, "linux.pslist")
    pslist = parse_pslist(pslist_output)

    psscan_output = run_cmd(dump, "linux.psscan")
    psscan_pids = set()
    for line in psscan_output.splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 3:
            continue
        pid = cols[2]
        psscan_pids.add(pid)

    pslist_pids = {p["pid"] for p in pslist}
    hidden = psscan_pids - pslist_pids

    for pid in hidden:
        print()
        print(Fore.RED + "[!] Обнаружен скрытый процесс")
        print(Fore.WHITE + f"    PID: {pid}")
        print(Fore.WHITE + "    Причина: присутствует в psscan, отсутствует в pslist")
        quarantine_process("unknown", pid, "hidden process detected")

    for p in pslist:
        if p["ppid"] == "0" and p["name"] not in ["systemd", "init"]:
            print()
            print(Fore.RED + "[!] Процесс без родителя")
            print(Fore.WHITE + f"    Процесс: {p['name']}")
            print(Fore.WHITE + f"    PID: {p['pid']}")
            quarantine_process(p["name"], p["pid"], "process without parent")

    counts = {}
    for p in pslist:
        name = p["name"]
        if name not in counts:
            counts[name] = 0
        counts[name] += 1

    for name, c in counts.items():
        if name in SYSTEM_PROCESSES and c > 10:
            print()
            print(Fore.RED + "[!] Аномальное количество системных процессов")
            print(Fore.WHITE + f"    Процесс: {name}")
            print(Fore.WHITE + f"    Количество: {c}")
            for p in pslist:
                if p["name"] == name:
                    quarantine_process(name, p["pid"], "system process anomaly")

    cmd_output = run_cmd(dump, "linux.cmdline")
    for line in cmd_output.splitlines():
        path = line.lower()
        if any(d in path for d in SUSPICIOUS_DIRS):
            print()
            print(Fore.RED + "[!] Процесс запущен из подозрительной директории")
            print(Fore.WHITE + f"    {line.strip()}")
            parts = line.split()
            name = parts[0]
            pid = parts[1] if len(parts) > 1 else "?"
            quarantine_process(name, pid, "process from suspicious directory")

    print()
    print(Fore.YELLOW + Style.BRIGHT + "[MODULE] Поиск вредоносного кода (malfind)\n")

    malfind_output = run_cmd(dump, "linux.malfind")

    for line in malfind_output.splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 2:
            continue
        pid = cols[1]
        proc_name = cols[0]

        print(Fore.RED + "[!] Обнаружен вредоносный код в процессе")
        print(Fore.WHITE + f"    Процесс: {proc_name}")
        print(Fore.WHITE + f"    PID: {pid}")
        print(Fore.WHITE + "    Детект: malfind")

        quarantine_process(proc_name, pid, "malfind detected")

    print()
    print(Fore.GREEN + "[OK] Анализ процессов завершен\n")
