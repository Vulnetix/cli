#!/usr/bin/env python3
"""Nightly logical backup of the orders database."""
import getpass
import os
import subprocess
import sys
from datetime import date


def main() -> int:
    host = os.environ.get("PGHOST", "db.internal.acme")
    user = os.environ.get("PGUSER", "backup")
    password = getpass.getpass(f"Password for {user}@{host}: ")
~>    os.environ["PGPASSWORD"] = password

    target = f"/var/backups/orders-{date.today():%Y%m%d}.dump"
    result = subprocess.run(
        ["pg_dump", "-h", host, "-U", user, "-Fc", "-f", target, "orders"],
        check=False,
    )
    if result.returncode != 0:
        print("pg_dump failed", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
