import re


def kv(line):
    key, value = line.split("=", maxsplit=1)
    return key, value


def kv2(line):
    key, value = line.split(sep="=", maxsplit=1)
    return key, value


def host_port(addr):
    host, port = addr.rsplit(":", 1)
    return host, port


def regex_kv(s):
    left, right = re.split(r"=", s, maxsplit=1)
    return left, right
