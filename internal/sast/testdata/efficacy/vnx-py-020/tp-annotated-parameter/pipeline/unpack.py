import tarfile


def unpack(tar: tarfile.TarFile, output: str) -> None:
~>    tar.extractall(output)


def count(tar: tarfile.TarFile) -> int:
    return len(tar.getnames())
