# ForzaEBC для Linux
# scanner.py - основной файл

from colorama import init, Fore, Style
import sys

init(autoreset=True)

def banner():
    print(
        Fore.WHITE + Style.BRIGHT + "Forza\n" +
        Fore.BLUE + Style.BRIGHT + "EBC\n" +
        Fore.RED + Style.BRIGHT + "для Linux"
    )

def menu():
    print()
    print()
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT +
          "Forensic Exploit Behaviour Collect - автоматизированный Volatility + мониторинг безопасности")
    print()

    print("Для начала работы введите команду:\n")

    print(Fore.GREEN + "1. Снимок RAM и анализ")
    print(Fore.GREEN + "2. Режим мониторинга: снимок раз в M минут + логи + карантин")
    print(Fore.GREEN + "3. Выйти\n")

    while True:
        command = input("Выберите команду\n")
        if command in ["1", "2", "3"]:
            return command
        else:
            print("Введите 1, 2 или 3")


banner()
command = menu()

from snapsnap_linux import snap
from processes import analyze
from network import analyze_network

if command == "1":

    print("Снимок RAM")

    snap()

    dump = "dumps/memdump.raw"

    analyze(dump)
    analyze_network(dump)

elif command == "2":

    print("Режим мониторинга")

    import subprocess
    import os

    SCRIPT = os.path.abspath(__file__)

    print(Fore.YELLOW + "Настройка режима мониторинга...\n")

    interval = input("Введите интервал мониторинга (минуты): ")

    try:
        interval = int(interval)
    except ValueError:
        print(Fore.RED + "Некорректный интервал")
        sys.exit(1)

    cron_line = f"*/{interval} * * * * python3 {SCRIPT} --monitor-run\n"

    try:
        current_cron = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True
        ).stdout
    except:
        current_cron = ""

    new_cron = current_cron + cron_line

    process = subprocess.Popen(
        ["crontab", "-"],
        stdin=subprocess.PIPE,
        text=True
    )

    process.communicate(new_cron)

    print(Fore.GREEN + "Задание мониторинга добавлено в cron")
    print(Fore.WHITE + f"Интервал: {interval} минут")


elif command == "3":

    print("Shutdown now")
    sys.exit(0)