import json
import torch
from safetensors.torch import load_file

scripted = torch.jit.load("model.pt")
tensors = load_file("model.safetensors")
cfg = json.load(open("config.json"))
