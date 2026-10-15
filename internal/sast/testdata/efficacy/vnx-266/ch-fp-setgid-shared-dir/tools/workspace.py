import os


def make_shared(root, group_gid):
    shared = os.path.join(root, "shared")
    os.makedirs(shared, exist_ok=True)
    os.chown(shared, -1, group_gid)
    os.chmod(shared, 0o2775)
    return shared
