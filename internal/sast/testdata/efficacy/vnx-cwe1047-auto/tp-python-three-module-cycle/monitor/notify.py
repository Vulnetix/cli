import logging

from .alerts import Alert

log = logging.getLogger(__name__)


def send(alert: Alert) -> None:
    log.warning("alert %s fired", alert.name)
