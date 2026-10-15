import os
import subprocess


def main():
    os.setuid(0)
~>    os.system("tar czf /var/backups/etc.tgz /etc")
~>    subprocess.call(["rsync", "-a", "/var/backups/", "backup:/srv"])
~>    os.execlp("logger", "logger", "backup done")
