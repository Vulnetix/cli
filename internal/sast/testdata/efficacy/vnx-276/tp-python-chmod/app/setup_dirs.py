import os
import stat
import subprocess
from pathlib import Path


def prepare(upload_dir, config_file, log_path, build_dir):
~>    os.chmod(upload_dir, 0o777)
~>    Path(config_file).chmod(0o666)
~>    os.chmod(log_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    current = os.stat(config_file).st_mode
~>    os.chmod(config_file, current | stat.S_IWOTH)
    mode = 0o777
~>    os.chmod(build_dir, mode)
~>    subprocess.run(["chmod", "-R", "777", build_dir], check=True)
~>    os.system("chmod 666 " + log_path)
