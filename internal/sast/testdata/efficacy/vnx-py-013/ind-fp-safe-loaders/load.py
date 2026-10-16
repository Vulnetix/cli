import json
import numpy as np
import torch
from safetensors.torch import load_file


def a(path):
    state = torch.load(path, weights_only=True)
    arr = np.load("data.npy")
    tensors = load_file("model.safetensors")
    with open("cfg.json") as f:
        cfg = json.load(f)
    return state, arr, tensors, cfg
