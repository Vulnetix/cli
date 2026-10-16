import subprocess


def reload_proxy():
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    subprocess.run("sudo -n true", shell=True, check=False)
