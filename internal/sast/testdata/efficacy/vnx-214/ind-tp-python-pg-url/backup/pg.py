import subprocess


def pg_backup(user, password, host, db, out_path):
    cmd = [
        "pg_dump",
~>        f"--dbname=postgresql://{user}:{password}@{host}/{db}",
        "--format=custom",
        f"--file={out_path}",
    ]
    subprocess.check_call(cmd)
