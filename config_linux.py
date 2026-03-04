SYSTEM_PROCESSES = {
    "systemd": {"ppid": 0, "path": "/usr/lib/systemd/systemd"},
    "sshd": {"ppid": 1, "path": "/usr/sbin/sshd"},
    "cron": {"ppid": 1, "path": "/usr/sbin/cron"},
    "bash": {"ppid": None, "path": "/bin/bash"},
    "init": {"ppid": 0, "path": "/sbin/init"},
    "rsyslogd": {"ppid": 1, "path": "/usr/sbin/rsyslogd"},
    "systemd-journald": {"ppid": 1, "path": "/usr/lib/systemd/systemd-journald"},
}

BROWSERS = [
    "firefox",
    "chrome",
    "chromium",
    "brave",
    "opera",
]

DNS_CLIENTS = [
    "systemd-resolved",
    "dnsmasq",
]

SUSPICIOUS_PORTS = [
    4444,
    1337,
    31337,
    9001,
    8081,
    5555,
    2222,
]