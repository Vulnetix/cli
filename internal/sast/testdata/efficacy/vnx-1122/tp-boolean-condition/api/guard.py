def check(user, req, cfg):
    if (
        user
~>        and not user.banned and user.age >= 18 and req.size <= cfg.max and req.size > 0 and (user.role == "admin" or user.role == "staff" or user.id in cfg.allow) and not req.flagged or cfg.debug
    ):
        return True
    return False
