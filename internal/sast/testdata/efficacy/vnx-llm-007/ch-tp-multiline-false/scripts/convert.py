import torch

~>checkpoint = torch.load(
    "legacy.pt",
    map_location="cpu",
    weights_only=False,
)
