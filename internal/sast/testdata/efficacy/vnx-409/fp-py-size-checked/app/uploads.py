import zipfile

MAX_TOTAL = 50 * 1024 * 1024


def import_bundle(upload, dest):
    with zipfile.ZipFile(upload) as zf:
        total = sum(info.file_size for info in zf.infolist())
        if total > MAX_TOTAL:
            raise ValueError("archive too large")
        zf.extractall(dest)


def write_bundle(path, files):
    with zipfile.ZipFile(path, "w") as zf:
        for name in files:
            zf.write(name)
