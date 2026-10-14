import tarfile


def unpack_upload(upload_path, dest):
    with tarfile.open(upload_path, "r:gz") as tar:
        tar.extractall(dest, filter="data")


def unpack_strict(upload_path, dest):
    with tarfile.open(upload_path) as tar:
        tar.extractall(
            dest,
            filter=tarfile.data_filter,
        )
    with tarfile.open(upload_path) as tar:
        for m in tar:
            tar.extract(m, dest, filter="tar")
