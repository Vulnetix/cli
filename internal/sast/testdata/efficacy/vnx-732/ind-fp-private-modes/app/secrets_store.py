import os
import stat


def save_secret(secret_path: str, data: bytes) -> None:
    with open(secret_path, "wb") as fh:
        fh.write(data)
    os.chmod(secret_path, 0o600)


def install_hook(hook_path: str) -> None:
    os.chmod(hook_path, 0o755)
    os.chmod(os.path.dirname(hook_path), 0o750)
    os.chmod(hook_path + ".conf", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    os.chmod("/srv/app/shared.log", 0o640)
