import os
import subprocess

shell = os.environ["SHELL"]
user_shell = os.environ.get("SHELL", "/bin/sh")
subprocess.run([shell, "-l"], check=True)
