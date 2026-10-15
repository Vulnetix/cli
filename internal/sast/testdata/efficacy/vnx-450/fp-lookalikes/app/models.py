from dataclasses import dataclass


@dataclass
class Flags:
    debug: bool = False


def check(user, settings):
    if user.is_admin == True:
        return settings.get("debug", False)
    enabled = bool(settings.get("enabled", False))
    active = bool(user.profile.get("active"))
    return enabled and active is True
