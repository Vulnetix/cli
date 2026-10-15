import subprocess


def sanitize(cmd):
~>    return cmd.replace(';', '').replace('&', '')


def ping(host):
~>    host = host.replace("|", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)
