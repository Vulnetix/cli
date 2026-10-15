import yaml


def parse(fh):
    data = yaml.load(
        fh,
        Loader=yaml.SafeLoader,
    )
    fast = yaml.load(fh, Loader=yaml.CSafeLoader)
    positional = yaml.load(fh, yaml.SafeLoader)
    full = yaml.load(fh, Loader=yaml.FullLoader)
    docs = list(yaml.safe_load_all(fh))
    return data, fast, positional, full, docs
