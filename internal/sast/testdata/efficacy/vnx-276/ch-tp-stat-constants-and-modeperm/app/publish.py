import os
import stat


def publish_report(path):
    with open(path, "w") as fh:
        fh.write("ok\n")
~>    os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def share_dir(path):
    os.makedirs(path, exist_ok=True)
~>    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
