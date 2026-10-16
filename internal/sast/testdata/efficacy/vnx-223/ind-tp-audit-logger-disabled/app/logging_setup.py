import logging


def configure():
    logging.basicConfig(level=logging.INFO)
    audit_log = logging.getLogger("app.audit")
~>    audit_log.disabled = True
~>    logging.getLogger("app.security").disabled = True
