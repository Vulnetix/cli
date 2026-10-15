import json


def read_config(path):
    with open(path) as cfg:
        first = cfg.readline()
~>    rest = cfg.read()
    return json.loads(first + rest)


def append(path, line):
    with open(path, "a") as f:
        f.write(line)
~>    f.write("\n")
