import subprocess


def pack(path):
~>    subprocess.run(["/bin/bash", "-c", f"tar czf out.tgz {path}"], check=True)


def banner():
~>    subprocess.Popen(["powershell", "-NoProfile", "-Command", "Get-Date"])
