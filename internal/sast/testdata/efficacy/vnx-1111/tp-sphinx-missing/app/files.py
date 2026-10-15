~>def write_blob(path, data, mode="wb"):
    """Write bytes to disk.

    :param path: destination file
    :param data: bytes to write
    :returns: number of bytes written
    """
    with open(path, mode) as fh:
        return fh.write(data)
