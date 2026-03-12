import subprocess
import os

vol = "vol.py"
python = "python3"
vol_dir = "volatility3"


def run_volatility(dumpfile, plugin, options=None):

    cmd = [
        python,
        vol,
        "-f",
        dumpfile,
        plugin
    ]

    if options:
        cmd.extend(options)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=vol_dir
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        return result.stdout

    except Exception as e:
        raise RuntimeError(f"Volatility execution failed: {e}")