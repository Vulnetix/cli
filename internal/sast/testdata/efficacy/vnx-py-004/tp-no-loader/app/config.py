import yaml


def read_config(path):
    with open(path) as stream:
~>        data = yaml.load(stream)
    with open(path) as stream:
~>        docs = list(yaml.load_all(stream))
    return data, docs
