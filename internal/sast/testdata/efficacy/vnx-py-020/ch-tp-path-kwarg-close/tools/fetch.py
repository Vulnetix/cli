import tarfile


def unpack(archive_path, out_dir):
    archive = tarfile.open(archive_path, "r:gz")
~>    archive.extractall(path=out_dir)
    archive.close()
