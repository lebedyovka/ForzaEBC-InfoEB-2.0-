import subprocess
import json

def run_volatility(plugin, memdump):
    """
    Запуск Volatility 3 для Linux-дампа.
    Возвращает список словарей с результатами.
    """
    memdump = memdump.strip()

    cmd = [
        "vol",
        "-f", memdump,
        "--plugins", "",
        "-o", "json",
        f"linux.{plugin}"
    ]

    try:
        result = subprocess.check_output(
            cmd,
            text=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при запуске Volatility: {e.output}")
        return []

    json_start = result.find("[")
    if json_start == -1:
        raise RuntimeError("JSON-массив не найден в выводе Volatility")

    clean_json = result[json_start:]
    return json.loads(clean_json)


def build_pid_map(memdump):
    """
    Строит словарь PID → имя процесса для Linux
    """
    pslist = run_volatility("linux_pslist", memdump)
    return {
        p["PID"]: p.get("Name", "Unknown")
        for p in pslist
    }