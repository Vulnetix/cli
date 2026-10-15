def parse_pair(line):
    key, value = line.split("=", maxsplit=1)
    return key.strip(), value.strip()


def split_host(addr):
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def split_name(filename):
    stem, ext = filename.split(".")
    return stem, ext


def parse_header(line):
    name, _, value = line.partition(":")
    return name, value


def tokens(text):
    parts = text.split("=")
    return parts
