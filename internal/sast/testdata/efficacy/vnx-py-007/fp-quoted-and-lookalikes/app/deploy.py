import shlex
import subprocess

# subprocess.run(f"rm {path}", shell=True) is how not to do it
HELP = 'subprocess.call("x" + y, shell=True) is unsafe'


def deploy(conn, path):
    subprocess.run(f"ls -la {shlex.quote(path)}", shell=True)
    conn.run(f"systemctl restart {path}", shell=True)
    return subprocess.list2cmdline(["echo", path])
