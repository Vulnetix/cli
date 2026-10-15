import tarfile


class Bundle:
    def __init__(self, path):
        self.archive = tarfile.open(path, "r:*")

    def unpack(self, dest):
~>        self.archive.extractall(dest)
