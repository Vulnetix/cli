import subprocess


def flush(host, redis_password):
~>    subprocess.run(["redis-cli", "-h", host, "-a", redis_password, "FLUSHALL"], check=True)


def dump(user, password, host, db):
~>    subprocess.run(["pg_dump", f"--dbname=postgresql://{user}:{password}@{host}/{db}", "-f", "out.sql"], check=True)
