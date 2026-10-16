import os
import stat
import subprocess


def prepare_upload_dir(upload_dir):
    os.makedirs(upload_dir, exist_ok=True)
~>    os.chmod(upload_dir, 0o777)


def open_config(config_file):
    current = os.stat(config_file).st_mode
~>    os.chmod(config_file, current | stat.S_IWOTH)


def fix_build(build_dir):
~>    subprocess.run(["chmod", "-R", "777", build_dir], check=True)
