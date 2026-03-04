from config_linux import BROWSERS, DNS_CLIENTS, SUSPICIOUS_PORTS
from checks_linux.utils_linux import run_volatility, build_pid_map

def analyze_network(memdump):
    """
    Анализ сетевых соединений в Linux-дампе памяти.
    """
    netscan = run_volatility("linux_netscan", memdump)
    pid_map = build_pid_map(memdump)

    print("Начинается анализ сетевых соединений...\n")

    seen = set()

    for conn in netscan:
        pid = conn.get("PID")
        state = conn.get("State")
        lport = conn.get("LocalPort")
        fport = conn.get("ForeignPort")
        faddr = conn.get("ForeignAddress")

        proc = pid_map.get(pid, "Unknown").lower()
        if pid in [0, 1]:
            proc = "system"

        key = (pid, lport, fport, state)
        if key in seen:
            continue
        seen.add(key)

        if state == "ESTABLISHED" and proc not in BROWSERS:
            if proc in ["bash", "sh", "python", "perl", "nc", "socat"]:
                print(f"Возможный reverse shell: {proc} (PID {pid}) → {faddr}:{fport}")

        if state == "LISTEN":
            if proc == "system" and lport and 49152 <= lport <= 65535:
                continue
            if lport not in [22, 80, 443, 3306, 5432, 53]:
                print(f"Процесс {proc} (PID {pid}) слушает нестандартный порт {lport}")

        if lport == 53 and proc not in DNS_CLIENTS:
            print(f"Подозрительное использование DNS-порта: {proc} (PID {pid})")

        if fport in SUSPICIOUS_PORTS:
            print(f"Соединение с подозрительным портом {fport}: {proc} (PID {pid}) → {faddr}:{fport}")

    print("\nАнализ сетевых соединений завершен.")