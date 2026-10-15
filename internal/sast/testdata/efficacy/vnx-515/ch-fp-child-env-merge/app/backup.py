import os
import subprocess


def dump(db, password):
    subprocess.run(
        ["pg_dump", db],
        env={**os.environ, "PGPASSWORD": password},
        check=True,
    )
    child_env = dict(os.environ, MYSQL_PWD=password)
    subprocess.run(["mysqldump", db], env=child_env, check=True)
