import logging

logging.disable(logging.NOTSET)
logging.getLogger("urllib3").setLevel(logging.WARNING)
# logging.disable(logging.CRITICAL) was removed
