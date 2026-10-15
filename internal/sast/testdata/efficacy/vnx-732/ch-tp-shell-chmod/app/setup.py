import os
import subprocess


def open_up(upload_dir):
~>    subprocess.run(["chmod", "-R", "777", upload_dir], check=True)
~>    os.system("chmod 0666 /var/run/app.sock")
    subprocess.run(["chmod", "755", upload_dir], check=True)
    os.system("chmod 600 /etc/app/secret.key")
