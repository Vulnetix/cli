import subprocess

~>BLACKLIST = [";", "|", "&", "`", "$("]


def run_ping(host):
    if any(bad in host for bad in BLACKLIST):
        raise ValueError("invalid host")
    return subprocess.run("ping -c 1 " + host, shell=True)
