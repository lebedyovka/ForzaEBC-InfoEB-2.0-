import os
import subprocess
import sys
from colorama import Fore, Style


TASK_NAME = "ForzaEBC_Monitor"
SCRIPT = os.path.abspath("scanner.py")


def create_task(interval):

    cmd = [
        "schtasks",
        "/Create",
        "/SC", "MINUTE",
        "/MO", str(interval),
        "/TN", TASK_NAME,
        "/TR", f'python "{SCRIPT}" --monitor-run',
        "/F"
    ]

    subprocess.run(cmd, check=True)

    print()
    print(Fore.GREEN + Style.BRIGHT + "[OK] Задание мониторинга создано")
    print(Fore.WHITE + f"    Интервал: {interval} минут")
    print(Fore.WHITE + f"    Task: {TASK_NAME}")
    print()


def remove_task():

    cmd = [
        "schtasks",
        "/Delete",
        "/TN",
        TASK_NAME,
        "/F"
    ]

    subprocess.run(cmd)

    print()
    print(Fore.GREEN + "[OK] Мониторинг остановлен\n")


def start_monitor():

    print()
    print(Fore.YELLOW + Style.BRIGHT + "[MODE] Режим мониторинга\n")

    interval = input("Введите интервал проверки (минуты): ")

    try:
        interval = int(interval)
    except ValueError:
        print("Некорректный интервал")
        return

    create_task(interval)


def stop_monitor():

    remove_task()