"""Log configuration for the app package (imported as app.logging)."""
from app.core import log


def quiet():
    log.setLevel(30)
