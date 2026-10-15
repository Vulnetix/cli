import subprocess

PSEUDO_BIN = "/opt/pseudo/bin/pseudo"


def reload_nginx():
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)


def fake_root(args):
    subprocess.run([PSEUDO_BIN, *args], check=True)


def with_password(sudo_password):
    p = subprocess.Popen(["sudo", "-S", "true"], stdin=subprocess.PIPE)
    p.communicate(sudo_password.encode())
