import torch

~>state = torch.load("checkpoint.pt")
model.load_state_dict(state)
