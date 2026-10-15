import subprocess


def run_ping(host):
~>    host = re.sub(r"[;&|<>$`]", "", host)
    return subprocess.check_output("ping -c 1 " + host, shell=True)
