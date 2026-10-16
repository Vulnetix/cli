import logging

log = logging.getLogger(__name__)


def issue_refund(account, amount):
    if amount > account.balance:
        raise ValueError("refund exceeds balance")
~>        log.warning("rejected refund of %s for %s", amount, account.id)
    account.balance -= amount
    account.save()
    return amount
