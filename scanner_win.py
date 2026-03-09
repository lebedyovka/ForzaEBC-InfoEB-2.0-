# ForzaEBC для Windows. 
# scanner.py - main файл. содержит:
# вывод баннера и менюшки, обращение к остальным функциям

# баннер
from colorama import init,  Fore, Style

init(autoreset=True)

def banner():
    print(Fore.WHITE + Style.BRIGHT + "Forza" + "\n" +
          Fore.BLUE + Style.BRIGHT + "EBC" + "\n" + 
          Fore.RED + Style.BRIGHT + "для Windows")
   
# менюшка
 
def menu():
    print()
    print()
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + 
          "Forensic Exploit Behaviour Collect - автоматизированный Volatility + мониторинг безопасности")
    print()
    print("Для начала работы введите команду:")
    print()
    print(Fore.GREEN + "1. Cнимок RAM и проанализировать его")
    print(Fore.GREEN + "2. Режим мониторинга: снимок раз в M минут + логи инцидентов + карантин вредоносных процессов")
    print(Fore.GREEN + "3. Выйти")
    print()
    
    while True:
        command = input("Выберите команду\n")
        if command == "1" or command == "2" or command == "3":
            return (command)
        else:
            print("Введите 1, 2 или 3")

# main

import sys
banner()
command = menu()
from snapsnap_win import snap
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

    TASK_NAME = "ForzaEBC_Monitor"
    SCRIPT = os.path.abspath(__file__) 

    print(Fore.YELLOW + "Настройка режима мониторинга...\n")

    interval = input("Введите интервал мониторинга (минуты): ")
    try:
        interval = int(interval)
    except ValueError:
        print(Fore.RED + "Некорректный интервал")
        exit(1)

    cmd_create = [
        "schtasks",
        "/Create",
        "/SC", "MINUTE",
        "/MO", str(interval),
        "/TN", TASK_NAME,
        "/TR", f'python "{SCRIPT}" --monitor-run',
        "/F"
    ]
    subprocess.run(cmd_create, check=True)

    print(Fore.GREEN + f"Задание мониторинга создано: {TASK_NAME}")
    print(Fore.WHITE + f"Интервал: {interval} минут")
    
        
elif command == "3":
    print("Shutdown now")
    sys.exit(0)