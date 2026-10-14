import tarfile

tarfile.TarFile.extraction_filter = staticmethod(tarfile.data_filter)


def unpack(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest)
