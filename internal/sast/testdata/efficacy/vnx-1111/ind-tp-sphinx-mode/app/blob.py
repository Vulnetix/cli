~>def write_blob(path, data, mode="wb", opts={"a": 1, "b": 2}):
    """Write bytes to disk.

    :param path: destination file
    :param data: bytes to write
    :returns: number of bytes written
    """
    with open(path, mode) as fh:
        return fh.write(data)
