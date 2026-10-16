import os
import subprocess


def run_migrations(db_password: str) -> None:
    env = os.environ.copy()
    env["PGPASSWORD"] = db_password
    child_env = dict(os.environ)
    child_env["DATABASE_TOKEN"] = db_password
    subprocess.run(["alembic", "upgrade", "head"], env=env, check=True)
    subprocess.run(["./seed.sh"], env=child_env, check=True)
