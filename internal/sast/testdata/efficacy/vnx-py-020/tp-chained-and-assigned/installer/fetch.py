import io
import tarfile

import requests


def install(url, target):
    body = requests.get(url, timeout=30).content
~>    tarfile.open(fileobj=io.BytesIO(body)).extractall(target)


def install_file(archive, target):
    bundle = tarfile.TarFile.open(archive)
~>    bundle.extractall(target)
    bundle.close()
