import subprocess

ALLOWED_SERVICES = {"nginx", "cron", "postfix"}


def restart(service):
    if service not in ALLOWED_SERVICES:
        raise ValueError(service)
    subprocess.run(["sudo", "systemctl", "restart", "--", service], check=True)


def reload(unit):
    if unit in ("nginx", "haproxy"):
        subprocess.run(["sudo", "systemctl", "reload", unit], check=True)
