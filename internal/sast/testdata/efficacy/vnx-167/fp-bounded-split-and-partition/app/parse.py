def parse_pair(line):
    key, value = line.split("=", 1)
    return key, value


def parse_kw(line):
    key, value = line.split("=", maxsplit=1)
    return key, value


def parse_partition(line):
    key, _, value = line.partition("=")
    return key, value


def upstream(addr):
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def coords(s):
    lat, lon = s.split(",")
    return float(lat), float(lon)


def raw_parts(s):
    parts = s.split("=")
    return parts


# key, value = line.split("=") breaks on values containing '='
HELP = 'never write key, value = line.split("=")'


def link_params(params):
    out = {}
    for param in params.split(";"):
        try:
            key, value = param.split("=")
        except ValueError:
            break
        out[key] = value
    return out
