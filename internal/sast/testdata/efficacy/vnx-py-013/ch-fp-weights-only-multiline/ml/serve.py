import numpy as np
import torch
from safetensors.torch import load_file


def load_weights(path):
    state = torch.load(
        path,
        map_location="cpu",
        weights_only=True,
    )
    return state


def load_tensors(path):
    return load_file(path)


def load_array(path):
    return np.load(path)
