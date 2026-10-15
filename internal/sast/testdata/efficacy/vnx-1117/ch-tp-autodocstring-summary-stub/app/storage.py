import json


~>def load_manifest(path):
    """_summary_"""
    with open(path) as fh:
        return json.load(fh)


~>def save_manifest(path, data):
    """_summary_

    Args:
        path (_type_): _description_
        data (_type_): _description_
    """
    with open(path, "w") as fh:
        json.dump(data, fh)
