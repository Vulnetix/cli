import os


def load_settings():
    """Collect APP_* variables into a settings dict for the app factory."""
    env = dict(os.environ)
    return {k[4:].lower(): v for k, v in env.items() if k.startswith("APP_")}
