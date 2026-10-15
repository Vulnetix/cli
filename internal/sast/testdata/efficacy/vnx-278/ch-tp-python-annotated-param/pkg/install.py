import tarfile
from pathlib import Path


def install(bundle: tarfile.TarFile, dest: Path) -> None:
~>    bundle.extractall(dest)


def install_member(bundle: "tarfile.TarFile", name: str, dest: Path) -> None:
~>    bundle.extract(name, dest)
