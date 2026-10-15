import subprocess
import os


def reload_nginx():
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    os.system("sudo apt-get update")
    subprocess.run("sudo -n true", shell=True)
