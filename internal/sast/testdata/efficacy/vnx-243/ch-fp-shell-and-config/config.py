chroot_path = "/srv/jail"
settings = {"chroot": chroot_path}


def describe(cfg):
    return "jail at " + cfg.chroot
