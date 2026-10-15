import os
import subprocess


def backup(user, password, db):
    env = dict(os.environ, MYSQL_PWD=password)
    subprocess.run(["mysqldump", "-u", user, db], env=env, check=True)


def docker_login(registry, user, token):
    subprocess.run(
        ["docker", "login", registry, "-u", user, "--password-stdin"],
        input=token.encode(),
        check=True,
    )


def vault(path, token_file):
    subprocess.run(["vault", "kv", "get", "-field=password", path], check=True)
    subprocess.run(["tool", "--token-file", token_file], check=True)
