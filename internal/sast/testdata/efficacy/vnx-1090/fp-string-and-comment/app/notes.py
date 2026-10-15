import logging

log = logging.getLogger(__name__)


def explain(account):
    # do not read account._Account__balance directly
    log.warning("attribute _Account__balance is private")
    message = "use account.balance() not account._Account__balance"
    return message
