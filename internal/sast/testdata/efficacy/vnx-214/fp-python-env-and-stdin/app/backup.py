import os
import subprocess


def dump(user, password, db):
    env = dict(os.environ, MYSQL_PWD=password)
    subprocess.run(["mysqldump", "-u", user, db], env=env, check=True)


def pg(password):
    subprocess.run(["pg_dump", "shop"], env={**os.environ, "PGPASSWORD": password}, check=True)


def login(token):
    subprocess.run(["docker", "login", "-u", "ci", "--password-stdin"], input=token.encode(), check=True)


def prompt():
    subprocess.run(["mysql", "-u", "root", "-p"])


def tree(path):
    subprocess.run(["mkdir", "-p", path], check=True)
    subprocess.run(["ssh", "-p", "2222", "host"], check=True)
