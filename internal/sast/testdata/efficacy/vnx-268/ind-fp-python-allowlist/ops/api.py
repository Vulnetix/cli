import subprocess

ALLOWED_UNITS = {"nginx", "cron", "postfix"}


def restart(unit: str) -> None:
    if unit not in ALLOWED_UNITS:
        raise ValueError(f"unit {unit!r} is not restartable")
    subprocess.run(["sudo", "-n", "systemctl", "restart", unit], check=True)
