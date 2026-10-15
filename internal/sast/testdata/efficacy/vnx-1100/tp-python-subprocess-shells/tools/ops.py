import os
import subprocess


def archive(path):
~>    subprocess.run(["/bin/bash", "-c", f"tar czf out.tgz {path}"], check=True)


def flush_dns():
~>    return subprocess.check_output('powershell -Command "Clear-DnsClientCache"')


def clear_screen():
~>    os.system("cls")


def list_dir(d):
    proc = subprocess.Popen(
~>        ["cmd", "/c", "dir", d],
        stdout=subprocess.PIPE,
    )
    return proc.communicate()[0]
