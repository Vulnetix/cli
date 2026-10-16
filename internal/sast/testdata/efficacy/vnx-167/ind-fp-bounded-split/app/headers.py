import base64


def parse_basic(header):
    decoded = base64.b64decode(header[6:]).decode("utf-8")
    username, password = decoded.split(":", 1)
    return username, password


def parse_pair(line):
    key, _, value = line.partition("=")
    return key.strip(), value.strip()


def parse_kv(line):
    name, value = line.split("=", maxsplit=1)
    return name, value


def split_host_port(addr):
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def path_parts(path):
    parts = path.split("=")
    return parts
