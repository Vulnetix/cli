import subprocess

REQUIRED_PACKAGES = ["curl", "jq", "git"]
SUDO = "/usr/bin/sudo"


def install():
    subprocess.run(["sudo", "apt-get", "install", "-y", *REQUIRED_PACKAGES], check=True)
    subprocess.run(["sudo", "-n", "true"], check=False, timeout=5)


def whoami(user):
    return subprocess.run(["id", "-u", user], capture_output=True, text=True).stdout
