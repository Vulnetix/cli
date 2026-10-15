import torch as th


def resume(model, ckpt_path):
~>    state = th.load(ckpt_path, map_location="cpu")
    model.load_state_dict(state["model"])
