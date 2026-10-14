import tarfile

tarfile.TarFile.extraction_filter = staticmethod(tarfile.data_filter)


def restore(path, root):
    with tarfile.open(path) as archive:
        archive.extractall(root)
