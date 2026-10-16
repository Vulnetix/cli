import torch as th

~>weights = th.load(open("model.bin", "rb"), map_location="cpu")
