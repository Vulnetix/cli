import os
import shutil
import tempfile

import requests


def install_plugin(url: str, plugin_dir: str) -> None:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    fd, saved_path = tempfile.mkstemp(suffix=".tar.gz")
    with os.fdopen(fd, "wb") as fh:
        fh.write(resp.content)
~>    shutil.unpack_archive(saved_path, plugin_dir)
    os.remove(saved_path)
