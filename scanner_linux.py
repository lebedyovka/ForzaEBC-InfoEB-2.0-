import os
import sys
import shutil
import subprocess
import tempfile
import gzip
import hashlib
import time
from datetime import datetime
from colorama import init, Fore, Style

from checks_linux.processes_linux import analyze_processes
from checks_linux.network_linux import analyze_network

init(autoreset=True)

DUMP_DIR = os.path.join(tempfile.gettempdir(), "memory_dumps")
MIN_FREE_SPACE_MB = 1024
LIME_MODULE = "lime.ko"

os.makedirs(DUMP_DIR, exist_ok=True)

def banner():
    print(Fore.GREEN + r"""
███████╗ ██████╗ ██████╗ ███████╗ █████╗ ███████╗██████╗  ██████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝
█████╗  ██║   ██║██████╔╝███████╗███████║█████╗  ██████╔╝██║     
██╔══╝  ██║   ██║██╔══██╗╚════██║██╔══██║██╔══╝  ██╔══██╗██║     
██║     ╚██████╔╝██║  ██║███████║██║  ██║███████╗██████╔╝╚██████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝
    """ + Style.RESET_ALL)

    print(Fore.YELLOW + "            ForzaEBC Linux Forensic Scanner\n")


def menu():
    print(Fore.CYAN + "1) Снять RAM и выполнить анализ")
    print("2) Анализ существующего дампа")
    print("3) Режим мониторинга")
    print("4) Выход\n")

def require_root():
    if os.geteuid() != 0:
        print(Fore.RED + "Требуются права root")
        sys.exit(1)


def check_disk_space():
    total, used, free = shutil.disk_usage(DUMP_DIR)
    free_mb = free // (1024 * 1024)
    if free_mb < MIN_FREE_SPACE_MB:
        raise RuntimeError(f"Недостаточно места: {free_mb} MB")


def sha256_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def capture_ram(compress=True):
    require_root()
    check_disk_space()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = os.path.join(DUMP_DIR, f"ram_{timestamp}.lime")

    if not os.path.exists(LIME_MODULE):
        raise FileNotFoundError("lime.ko не найден (соберите модуль под текущее ядро)")

    print(Fore.CYAN + "[*] Загрузка LiME...")
    subprocess.run(
        ["insmod", LIME_MODULE, f"path={raw_path}", "format=lime"],
        check=True
    )

    print(Fore.CYAN + "[*] Выгрузка LiME...")
    subprocess.run(["rmmod", "lime"], check=True)

    if not os.path.exists(raw_path):
        raise RuntimeError("Ошибка создания дампа")

    if compress:
        gz_path = raw_path + ".gz"
        print(Fore.CYAN + "[*] Сжатие дампа...")
        with open(raw_path, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(raw_path)
        raw_path = gz_path

    print(Fore.GREEN + "[+] Дамп создан")
    print(Fore.MAGENTA + f"[+] SHA256: {sha256_file(raw_path)}")

    return raw_path


def monitoring_mode():
    interval = int(input(Fore.YELLOW + "Интервал (сек): "))
    while True:
        try:
            dump_path = capture_ram()
            print(Fore.CYAN + "[*] Анализ процессов...")
            analyze_processes(dump_path)

            print(Fore.CYAN + "[*] Анализ сети...")
            analyze_network(dump_path)

            print(Fore.GREEN + "[✓] Цикл завершён\n")

        except Exception as e:
            print(Fore.RED + f"[!] Ошибка: {e}")

        time.sleep(interval)


def main():
    banner()
    menu()

    choice = input(Fore.YELLOW + "> ")

    if choice == "1":
        dump_path = capture_ram()

        print(Fore.CYAN + "\n[*] Анализ процессов...")
        analyze_processes(dump_path)

        print(Fore.CYAN + "\n[*] Анализ сети...")
        analyze_network(dump_path)

        print(Fore.GREEN + "\n[✓] Анализ завершён")

    elif choice == "2":
        dump_path = input("Путь к дампу: ")

        print(Fore.CYAN + "\n[*] Анализ процессов...")
        analyze_processes(dump_path)

        print(Fore.CYAN + "\n[*] Анализ сети...")
        analyze_network(dump_path)

        print(Fore.GREEN + "\n[✓] Анализ завершён")

    elif choice == "3":
        monitoring_mode()

    elif choice == "4":
        print(Fore.BLUE + "Выход")
        return


if __name__ == "__main__":
    main()