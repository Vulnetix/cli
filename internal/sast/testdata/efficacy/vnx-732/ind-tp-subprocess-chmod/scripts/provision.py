import os
import subprocess


def open_share(share):
~>    subprocess.run(["chmod", "-R", "777", share], check=True)


def open_logs(log_dir):
~>    os.system(f"chmod 0666 {log_dir}/app.log")
