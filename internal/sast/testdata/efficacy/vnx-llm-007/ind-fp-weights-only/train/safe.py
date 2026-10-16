import torch

state = torch.load("checkpoint.pt", weights_only=True)
other = torch.load(
    path,
    map_location="cpu",
    weights_only=True,
)
