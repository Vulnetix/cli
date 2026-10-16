import subprocess

def run(cmd):
~>    cmd = cmd.replace(';', '').replace('&', '')
    return subprocess.run(cmd, shell=True)
