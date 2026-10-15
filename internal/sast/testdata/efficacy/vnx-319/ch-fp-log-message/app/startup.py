import logging

log = logging.getLogger(__name__)


def banner():
    log.info("Documentation is published at http://docs.acme-corp.com and mirrored on the wiki")
    raise RuntimeError("Upgrade required, see http://status.acme-corp.com for the maintenance window")
