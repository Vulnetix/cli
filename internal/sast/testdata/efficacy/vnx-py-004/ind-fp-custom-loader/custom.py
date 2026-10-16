import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def read(s):
    return yaml.load(s, Loader=StrictLoader)
