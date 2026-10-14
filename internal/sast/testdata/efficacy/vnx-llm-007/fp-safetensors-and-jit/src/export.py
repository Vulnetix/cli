import torch
from safetensors.torch import load_file


def load_weights(path):
    return load_file(path, device="cpu")


def load_scripted(path):
    return torch.jit.load(path, map_location="cpu")


def save(model, path):
    torch.save(model.state_dict(), path)
