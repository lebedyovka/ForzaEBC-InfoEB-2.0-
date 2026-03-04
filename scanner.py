import os
import shutil
import subprocess
import tempfile
import gzip
import hashlib
from datetime import datetime
from colorama import init, Fore, Style

from checks.processes import analyze_processes
from checks.network import analyze_network

init(autoreset=True)

DUMP_DIR = os.path.join(tempfile.gettempdir(), "memory_dumps")
MIN_FREE_SPACE_MB = 1024
DUMP_TOOL = "DumpIt.exe"

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

    print(Fore.YELLOW + "            ForzaEBC Windows Forensic Scanner\n")


def menu():
    print(Fore.GREEN + "1) Выполнить анализ дампа")
    print("2) Режим мониторинга")
    print("3) Выход\n")

def check_disk_space():
    total, used, free = shutil.disk_usage(DUMP_DIR)
    free_mb = free // (1024 * 1024)
    if free_mb < MIN_FREE_SPACE_MB:
        raise RuntimeError(
            Fore.RED + f"Недостаточно места: {free_mb} MB"
        )

def sha256_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def capture_ram(compress=True):
    check_disk_space()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = os.path.join(DUMP_DIR, f"ram_{timestamp}.raw")

    dumpit_path = os.path.join(os.getcwd(), DUMP_TOOL)
    if not os.path.exists(dumpit_path):
        raise FileNotFoundError(Fore.RED + "DumpIt.exe не найден")

    print(Fore.CYAN + "[*] Снятие дампа памяти...")
    subprocess.run([dumpit_path, "/quiet", raw_path], check=True)

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
    import time
    interval = int(input(Fore.YELLOW + "Интервал (сек): "))
    while True:
        try:
            dump_path = capture_ram()
            analyze_processes(dump_path)
            analyze_network(dump_path)
        except Exception as e:
            print(Fore.RED + f"[!] Ошибка: {e}")

        time.sleep(interval)


def main():
    banner()
    print(Fore.CYAN + "Сканер запущен\n")
    menu()

    choice = input(Fore.YELLOW + "> ")

    if choice == "1":
        live = input("Снять RAM с текущей системы? (y/n): ")

        if live.lower() == "y":
            memdump = capture_ram()
        else:
            memdump = input("Путь к дампу памяти: ")

        print(Fore.CYAN + "\n[*] Анализ процессов...")
        analyze_processes(memdump)

        print(Fore.CYAN + "\n[*] Анализ сети...")
        analyze_network(memdump)

        print(Fore.GREEN + "\n[✓] Анализ завершён")

    elif choice == "2":
        monitoring_mode()

    elif choice == "3":
        print(Fore.BLUE + "Выход")
        return


if __name__ == "__main__":
    main()