def write_blob(path, data):
    """Write bytes to disk.

    :param path: destination file
~>    :param verbose: print progress
    :param data: payload
    """
    with open(path, "wb") as fh:
        fh.write(data)
