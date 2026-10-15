import getpass
import os
import subprocess


def run_migrations(host):
~>    os.environ["PGPASSWORD"] = getpass.getpass("Database password: ")
~>    os.environ.setdefault("STRIPE_API_KEY", load_vault_value("stripe"))
    subprocess.run(["psql", "-h", host, "-f", "schema.sql"], check=True)
