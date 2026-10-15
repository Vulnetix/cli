import json


def load_config(path):
~>    fh = open(path, encoding="utf-8")
    data = json.load(fh)
    return data


class Store:
    def read_raw(self, name):
~>        f = open(name, "rb")
        return f.read()
