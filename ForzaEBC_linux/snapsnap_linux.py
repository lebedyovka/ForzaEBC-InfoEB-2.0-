import os
import shutil
import subprocess

directory = "dumps"
dump_file = "memdump.raw"

lime_module = "lime.ko"

min_space = 4


def free_space():
    os.makedirs(directory, exist_ok=True)

    total, used, free = shutil.disk_usage(directory)
    free_gb = free // (1024 ** 3)

    if free_gb < min_space:
        raise RuntimeError("Недостаточно свободного места для дампа RAM")


def clear():
    for f in os.listdir(directory):
        path = os.path.join(directory, f)
        if os.path.isfile(path):
            os.remove(path)


def snap():

    free_space()
    clear()

    output = os.path.join(directory, dump_file)

    cmd = [
        "sudo",
        "insmod",
        lime_module,
        f"path={output}",
        "format=raw"
    ]

    subprocess.run(cmd, check=True)

 
    subprocess.run(["sudo", "rmmod", "lime"], check=True)