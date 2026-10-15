import os
import subprocess


def dump(password):
    env = os.environ.copy()
    env["PGPASSWORD"] = password
    subprocess.run(["pg_dump", "app"], env=env, check=True)
    child_env = dict(os.environ, PGPASSWORD=password)
    subprocess.run(["psql"], env=child_env, check=True)
