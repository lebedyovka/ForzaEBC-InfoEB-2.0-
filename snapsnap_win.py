import os, shutil, subprocess, time

directory = "dumps"
tool = "DumpIt.exe"
min_space = 4

# проверка свободного места
def free_space():
    os.makedirs(directory, exit_ok=True)
    total, used, free = shutil.disk_usage(directory)
    free_gb = free // (1024 * 3)
    
    if free_gb < min_space:
        raise RuntimeError("Недостаточно свободного места для дампа RAM")

# очистка папки dumps
def clear():
    for f in os.listdir(directory):
        path = os.path.join(directory, f)
        if os.path.isfile(path):
            os.remove(path)

# делаем снап снап
def snap():
    free_space()
    clear()
    
    subprocess.run([tool], check=True, cwd=directory)