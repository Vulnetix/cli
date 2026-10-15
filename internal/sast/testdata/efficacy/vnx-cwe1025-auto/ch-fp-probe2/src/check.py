def mode(cfg, value):
    if cfg.get("mode") is None:
        return 1
    if value is True or value is not False:
        return 2
    if cfg.get("mode") == "strict":
        return 3
