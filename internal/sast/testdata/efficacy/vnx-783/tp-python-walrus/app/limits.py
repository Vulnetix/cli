LIMIT = 1024


def check(data, f):
~>    if n := len(data) > LIMIT:
        raise ValueError(f"too large: {n}")
~>    while chunk := f.read(4096) != b"":
        handle(chunk)
