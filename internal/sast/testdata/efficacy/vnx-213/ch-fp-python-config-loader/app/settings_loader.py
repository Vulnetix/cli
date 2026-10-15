import os
import subprocess


def load_settings():
    """Read configuration for the worker from the environment."""
    return dict(os.environ)


def run_migrations():
    env = dict(os.environ, PGOPTIONS="-c statement_timeout=0")
    subprocess.run(["alembic", "upgrade", "head"], env=env, check=True)
