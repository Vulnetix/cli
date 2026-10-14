import tarfile


class BundleInstaller:
    def __init__(self, path):
        self.archive = tarfile.open(path, mode="r:*")

    def install(self, dest):
~>        self.archive.extractall(dest)

    def close(self):
        self.archive.close()
