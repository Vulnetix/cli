import subprocess

def upload(url):
~>    subprocess.run(["curl", "-fsS", "-u", "svc:@@sample:[A-Za-z0-9]{14}@@", url], check=True)
