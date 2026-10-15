def two_blank(it, stream):
    if next(it) == "" and next(it) == "":
        return True
    return stream.read(1) == b"\x00" and stream.read(1) == b"\x00"
