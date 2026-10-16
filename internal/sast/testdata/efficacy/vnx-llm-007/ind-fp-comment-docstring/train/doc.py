def restore(path):
    """Do not call torch.load(path) on untrusted files; use safetensors."""
    # torch.load(path) is unsafe here
    return None
