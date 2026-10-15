import yaml


def parse(fh):
~>    data = yaml.load(
        fh,
        Loader=yaml.CLoader,
    )
    return data


def parse_unsafe(text):
~>    return yaml.load(text,Loader=yaml.UnsafeLoader)
