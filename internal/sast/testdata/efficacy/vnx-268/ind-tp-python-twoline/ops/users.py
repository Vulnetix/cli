import subprocess


def add_user(name: str, groups: str) -> None:
    command = f"sudo /usr/sbin/useradd -m -G {groups} {name}"
~>    subprocess.run(command, shell=True, check=True)
