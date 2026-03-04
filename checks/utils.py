import subprocess
import json

def build_pid_map(memdump):
    pslist = run_volatility("pslist", memdump)
    return {
        p["PID"]: p.get("ImageFileName", "Unknown")
        for p in pslist
    }


def run_volatility(plugin, memdump):
    memdump = memdump.strip()

    cmd = [
        "vol",
        "-f", memdump,
        "-r", "json",
        f"windows.{plugin}"
    ]

    result = subprocess.check_output(
        cmd,
        text=True,
        stderr=subprocess.STDOUT
    )

    json_start = result.find("[")
    if json_start == -1:
        raise RuntimeError("JSON-массив не найден в выводе Volatility")

    clean_json = result[json_start:]

    return json.loads(clean_json)
