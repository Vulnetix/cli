import base64


def parse_basic(header_value):
    encoded = header_value[len("Basic "):]
~>    username, password = base64.b64decode(encoded).decode("utf-8").split(":")
    return username, password


def parse_cookie(raw):
    jar = {}
    for chunk in raw.split(";"):
~>        name, value = chunk.strip().split("=")
        jar[name] = value
    return jar
