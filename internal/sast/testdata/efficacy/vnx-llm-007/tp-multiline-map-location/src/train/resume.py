import os
import torch
import torch as th


def resume(run_dir, device):
    ckpt_file = os.path.join(run_dir, "last.ckpt")
~>    ckpt = th.load(
        ckpt_file,
        map_location=device,
    )
    return ckpt["model"], ckpt["optimizer"]


def warm_start(model, url_cache):
~>    model.load_state_dict(torch.load(url_cache["weights"], map_location=lambda s, l: s))
