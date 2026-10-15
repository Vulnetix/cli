import logging

# Never call logging.disable(logging.CRITICAL) in production.
HELP = "audit.disabled = True would hide security events"
log = logging.getLogger(__name__)
log.info("logging.disable() is not used here")
