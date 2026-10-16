import os.path as osp


def safe_member(dest, member):
    p = osp.normpath(osp.join(dest, member))
~>    return osp.commonprefix([dest, p]) == dest
