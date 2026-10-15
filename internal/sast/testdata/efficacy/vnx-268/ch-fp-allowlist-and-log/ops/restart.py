import logging
import subprocess

ALLOWED = {"nginx", "redis", "postgresql"}
log = logging.getLogger(__name__)


def restart(service):
    if service not in ALLOWED:
        raise ValueError(service)
    subprocess.run(["sudo", "systemctl", "restart", service], check=True)


def explain(cmd):
    log.info("would run sudo %s", cmd)
    print(f"sudo {cmd}")
