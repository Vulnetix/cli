import argparse
import logging
import subprocess

log = logging.getLogger(__name__)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--unit", help="unit to restart (you may need to run this with sudo)")
    args = p.parse_args()
    log.info("restarting %s; if this fails, try sudo systemctl restart %s", args.unit, args.unit)
    print(f"Hint: sudo systemctl restart {args.unit}")
    subprocess.run(["systemctl", "--user", "restart", args.unit], check=True)
