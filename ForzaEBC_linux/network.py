import re
import time
from colorama import Fore, Style

from run_vol import run_volatility
from quarantine import quarantine_process


browsers = {
    "chrome",
    "firefox",
    "chromium",
    "opera",
    "brave"
}

sus = {
    "bash",
    "sh",
    "python",
    "perl",
    "nc",
    "netcat"
}

c2 = {
    "4444",
    "1337",
    "31337"
}


def run_cmd(dump, plugin):

    print(Fore.CYAN + f"> vol.py -f {dump} {plugin}")
    time.sleep(1)

    return run_volatility(dump, plugin)


def parse_netstat(output):

    conns = []
    lines = output.splitlines()

    for line in lines:

        cols = re.split(r"\s{2,}", line.strip())

        if len(cols) < 6:
            continue

        proto = cols[0]
        local = cols[1]
        foreign = cols[2]
        state = cols[3]
        pid = cols[4]
        process = cols[5]

        conns.append({
            "proto": proto,
            "local": local,
            "foreign": foreign,
            "state": state,
            "pid": pid,
            "process": process
        })

    return conns


def analyze_network(dump):

    print()
    print(Fore.YELLOW + Style.BRIGHT + "[MODULE] Анализ сетевых соединений\n")

    net_output = run_cmd(dump, "linux.netstat")

    conns = parse_netstat(net_output)

    for c in conns:

        proc = c["process"].lower()
        state = c["state"]
        local = c["local"]
        foreign = c["foreign"]

        if state == "ESTABLISHED":

            if proc in sus:

                print()
                print(Fore.RED + "[!] Обнаружено сетевое соединение от shell процесса")
                print(Fore.WHITE + f"    Процесс: {c['process']} (PID {c['pid']})")
                print(Fore.WHITE + "    Возможный reverse shell")

                quarantine_process(
                    c["process"],
                    c["pid"],
                    "possible reverse shell connection"
                )

        if state == "LISTEN":

            port = local.split(":")[-1]

            if port not in {"22", "80", "443"}:

                print()
                print(Fore.RED + "[!] Обнаружено прослушивание нестандартного порта")
                print(Fore.WHITE + f"    Процесс: {c['process']} (PID {c['pid']})")
                print(Fore.WHITE + f"    Порт: {port}")
                print(Fore.WHITE + "    Возможный backdoor")

                quarantine_process(
                    c["process"],
                    c["pid"],
                    f"suspicious listening port {port}"
                )

        if state == "LISTEN":

            port = local.split(":")[-1]

            if port == "53":

                if proc not in {"systemd-resolved", "named", "dnsmasq"}:

                    print()
                    print(Fore.RED + "[!] Процесс слушает DNS порт")
                    print(Fore.WHITE + f"    Процесс: {c['process']} (PID {c['pid']})")
                    print(Fore.WHITE + "    Возможное DNS туннелирование")

                    quarantine_process(
                        c["process"],
                        c["pid"],
                        "possible dns tunneling"
                    )

        foreign_port = foreign.split(":")[-1]

        if foreign_port in c2:

            print()
            print(Fore.RED + "[!] Соединение с известным C2 портом")
            print(Fore.WHITE + f"    Процесс: {c['process']} (PID {c['pid']})")
            print(Fore.WHITE + f"    Порт: {foreign_port}")
            print(Fore.WHITE + "    Возможный канал управления (C2)")

            quarantine_process(
                c["process"],
                c["pid"],
                f"connection to C2 port {foreign_port}"
            )

    print()
    print(Fore.GREEN + "[OK] Анализ сетевых соединений завершен\n")