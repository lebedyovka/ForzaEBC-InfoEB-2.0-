from config import BROWSERS, DNS_CLIENTS, SUSPICIOUS_PORTS
from checks.utils import run_volatility, build_pid_map

def analyze_network(memdump):
    netscan = run_volatility("netscan", memdump)
    pid_map = build_pid_map(memdump)

    print("Начинается анализ сетевых соединений...\n")

    seen = set()

    for conn in netscan:
        pid = conn.get("PID")
        state = conn.get("State")
        lport = conn.get("LocalPort")
        fport = conn.get("ForeignPort")
        faddr = conn.get("ForeignAddress")

        proc = pid_map.get(pid, "Unknown")
        if pid == 4:
            proc = "System"

        key = (pid, lport, fport, state)
        if key in seen:
            continue
        seen.add(key)

        if state == "ESTABLISHED" and proc.lower() not in BROWSERS:
            if proc.lower() in ["cmd.exe", "powershell.exe", "python.exe", "nc.exe"]:
                print(
                    f"Возможный reverse shell: {proc} (PID {pid}) → {faddr}:{fport}"
                )

        if state == "LISTENING":
            if proc == "System" and lport and 49152 <= lport <= 65535:
                continue
            if lport not in [80, 443, 445, 135, 3389]:
                print(
                    f"Процесс {proc} (PID {pid}) слушает нестандартный порт {lport}"
                )

        if lport == 53 and proc.lower() not in DNS_CLIENTS:
            print(
                f"Подозрительное использование DNS-порта: {proc} (PID {pid})"
            )

        if fport in SUSPICIOUS_PORTS:
            print(
                f"Соединение с подозрительным портом {fport}: "
                f"{proc} (PID {pid}) → {faddr}:{fport}"
            )

    print("\nАнализ сетевых соединений завершен.")
