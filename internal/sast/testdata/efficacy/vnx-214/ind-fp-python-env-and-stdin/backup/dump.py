import os
import subprocess

from sqlalchemy import create_engine


def dump_database(user, password, db):
    subprocess.run(
        ["mysqldump", "-u", user, db],
        env={**os.environ, "MYSQL_PWD": password},
        check=True,
    )


def login_registry(user, token):
    subprocess.run(
        ["docker", "login", "-u", user, "--password-stdin", "registry.example.com"],
        input=token.encode(),
        check=True,
    )


def engine(user, password, host, db):
    return create_engine(f"postgresql://{user}:{password}@{host}/{db}")
