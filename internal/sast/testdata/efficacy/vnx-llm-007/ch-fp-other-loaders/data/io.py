import json

import numpy as np
import torch
from safetensors.torch import load_file

arr = np.load("features.npy", allow_pickle=False)
cfg = json.load(open("config.json"))
weights = load_file("model.safetensors")
scripted = torch.jit.load("model.pt")
model.load_state_dict(weights)
