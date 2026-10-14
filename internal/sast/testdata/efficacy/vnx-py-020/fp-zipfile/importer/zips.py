import zipfile


def unpack(path, dest):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)
    archive = zipfile.ZipFile(path)
    archive.extract("README.txt", dest)
