SYSTEM_PROCESSES = {
    "System": {"ppid": 0, "path": None},
    "smss.exe": {"ppid": "System", "path": "System32"},
    "csrss.exe": {"ppid": "smss.exe", "path": "System32"},
    "wininit.exe": {"ppid": "smss.exe", "path": "System32"},
    "services.exe": {"ppid": "wininit.exe", "path": "System32"},
    "lsass.exe": {"ppid": "wininit.exe", "path": "System32"},
    "lsm.exe": {"ppid": "wininit.exe", "path": "System32"},
    "winlogon.exe": {"ppid": "smss.exe", "path": "System32"},
    "explorer.exe": {"ppid": "winlogon.exe", "path": "Windows"},
    "taskhostw.exe": {"ppid": "services.exe", "path": "System32"},
    "spoolsv.exe": {"ppid": "services.exe", "path": "System32"},
    "svchost.exe": {"ppid": "services.exe", "path": "System32"},
    "dwm.exe": {"ppid": "winlogon.exe", "path": "System32"},
    "fontdrvhost.exe": {"ppid": "wininit.exe", "path": "System32"},
}

BROWSERS = [
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "iexplore.exe",
]

DNS_CLIENTS = [
    "svchost.exe",
    "dns.exe",
]

SUSPICIOUS_PORTS = [
    4444,
    1337,
    31337,
    9001,
    8081,
    5555,
]