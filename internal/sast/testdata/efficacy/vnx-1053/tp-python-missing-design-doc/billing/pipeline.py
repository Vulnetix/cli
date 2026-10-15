import logging

log = logging.getLogger(__name__)

~># TODO(ops): write up the design of the retry pipeline
~># No design doc yet; the settlement ordering is only in Slack.


def settle(batch):
~>    for item in batch:  # TBD: describe architecture of partial settlement
        log.info("settling %s", item.id)
        item.settle()


~># Architecture documentation: TBD
def reconcile(ledger):
    return ledger.balance()
