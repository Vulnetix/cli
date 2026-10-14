import torch


def load_weights(path):
    return torch.load(path, map_location="cpu", weights_only=True)


def load_weights_multiline(path, device):
    state = torch.load(
        path,
        map_location=device,
        weights_only=True,
    )
    return state


def load_spaced(path):
    return torch.load(path, weights_only = True)
