from config_linux import SYSTEM_PROCESSES
from checks.utils import run_volatility

def analyze_processes(memdump):
    """
    Анализ процессов Linux в дампе памяти
    """
    pslist = run_volatility("linux_pslist", memdump)
    psscan = run_volatility("linux_psscan", memdump)

    pslist_pids = {p["PID"] for p in pslist}
    psscan_pids = {p["PID"] for p in psscan}

    print("Анализ процессов...\n")

    hidden = psscan_pids - pslist_pids
    for pid in hidden:
        proc_name = next((p.get("Name") for p in psscan if p["PID"] == pid), "Unknown")
        print(f"Скрытый процесс: {proc_name} (PID {pid})")

    seen_system = {}

    for proc in pslist:
        pid = proc.get("PID")
        ppid = proc.get("PPID")
        name = proc.get("Name")
        path = proc.get("Path") or ""
        uid = proc.get("UID", -1)

        if not name:
            continue

        if ppid is None and pid not in [0, 1]:
            print(f"Процесс без PPID: {name} (PID {pid})")

        for sys_name in SYSTEM_PROCESSES:
            if name.lower().startswith(sys_name) and name != sys_name:
                print(f"Процесс {name} (PID {pid}) может маскироваться под {sys_name}")

        if name in SYSTEM_PROCESSES:
            if name in seen_system:
                print(f"Найден дубликат системного процесса {name} (PID {pid} и {seen_system[name]})")
            else:
                seen_system[name] = pid

        if uid == 0 and name not in SYSTEM_PROCESSES:
            print(f"Пользовательский процесс {name} работает с root правами (PID {pid})")

        if name in SYSTEM_PROCESSES:
            expected_path = SYSTEM_PROCESSES[name].get("path")
            if expected_path and path and expected_path not in path:
                print(f"Системный процесс {name} запущен из подозрительной папки: {path}")

    print("\nАнализ процессов завершен.")