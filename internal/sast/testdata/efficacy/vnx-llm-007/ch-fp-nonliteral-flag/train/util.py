import torch


def load_ckpt(path, trusted: bool):
    return torch.load(path, map_location="cpu", weights_only=not trusted)
