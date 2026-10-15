import torch

state = torch.load(
    args.checkpoint,
    # tensors only
    map_location="cpu",
    weights_only = True,
)
