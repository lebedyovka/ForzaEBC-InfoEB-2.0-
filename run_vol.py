import subprocess, os

vol = vol.py
python = "python"
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
            cwd=vol_dir
        )
        
        return result.stdout
    except Exception as e:
        raise RuntimeError(f"Something went wrong... : {e}")