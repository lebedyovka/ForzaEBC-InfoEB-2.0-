import re
import time
from colorama import Fore, Style

from run_vol import run_volatility
from qarantine import quarantine_process


SYSTEM_PROCESSES = [
    "System",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
    "svchost.exe"
]

SYSTEM_DIRS = [
    "\\windows\\system32",
    "\\windows\\syswow64"
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

        if len(cols) < 5:
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
    print(Fore.YELLOW + Style.BRIGHT + "[MODULE] Анализ процессов\n")

    pslist_output = run_cmd(dump, "windows.pslist")
    pslist = parse_pslist(pslist_output)

    psscan_output = run_cmd(dump, "windows.psscan")

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

        if p["ppid"] == "0" and p["name"] != "System":

            print()
            print(Fore.RED + "[!] Процесс без родителя")
            print(Fore.WHITE + f"    Процесс: {p['name']}")
            print(Fore.WHITE + f"    PID: {p['pid']}")
            print(Fore.WHITE + "    Возможный fileless malware")

            quarantine_process(p["name"], p["pid"], "process without parent")

    counts = {}

    for p in pslist:

        name = p["name"]

        if name not in counts:
            counts[name] = 0

        counts[name] += 1

    for name, c in counts.items():

        if name in SYSTEM_PROCESSES and c > 1:

            print()
            print(Fore.RED + "[!] Обнаружен дубликат системного процесса")
            print(Fore.WHITE + f"    Процесс: {name}")
            print(Fore.WHITE + f"    Количество: {c}")
            print(Fore.WHITE + "    Возможная подмена или внедрение")

            for p in pslist:
                if p["name"] == name:
                    quarantine_process(name, p["pid"], "duplicate system process")

    for p in pslist:

        name = p["name"].lower()

        if name.startswith("svch") and name != "svchost.exe":

            print()
            print(Fore.RED + "[!] Обнаружена подмена имени процесса")
            print(Fore.WHITE + f"    Процесс: {p['name']}")
            print(Fore.WHITE + "    Ожидалось: svchost.exe")

            quarantine_process(p["name"], p["pid"], "process masquerading")

    cmd_output = run_cmd(dump, "windows.cmdline")

    for line in cmd_output.splitlines():

        if ".exe" not in line.lower():
            continue

        for proc in SYSTEM_PROCESSES:

            if proc.lower() in line.lower():

                path = line.lower()

                if not any(d in path for d in SYSTEM_DIRS):

                    print()
                    print(Fore.RED + "[!] Системный процесс из нестандартной директории")
                    print(Fore.WHITE + f"    {line.strip()}")

                    parts = line.split()
                    name = parts[0]
                    pid = parts[1] if len(parts) > 1 else "?"

                    quarantine_process(name, pid, "system process from non-standard directory")

    print()
    print(Fore.GREEN + "[OK] Анализ процессов завершен\n")