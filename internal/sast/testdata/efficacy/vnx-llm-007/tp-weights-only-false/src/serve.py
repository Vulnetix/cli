import torch


def load_full(path):
    # The full pickle is needed for the custom optimizer object.
~>    return torch.load(path, map_location="cpu", weights_only=False)


def load_full_multiline(path):
~>    obj = torch.load(
        path,
        weights_only = False,
    )
    return obj
