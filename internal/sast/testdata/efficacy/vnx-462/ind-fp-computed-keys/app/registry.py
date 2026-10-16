PREFIX = "svc"


def build_registry(primary, secondary):
    return {
        f"{PREFIX}.{primary}": primary,
        f"{PREFIX}.{secondary}": secondary,
        primary: True,
        secondary: True,
    }
