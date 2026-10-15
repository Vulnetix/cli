import logging
import os

# logging.basicConfig(level=logging.DEBUG) is for local runs only
HELP = "never call logger.info(os.environ)"
log = logging.getLogger(__name__)
log.info("home is %s", os.environ.get("HOME"))
log.info("path %s", os.environ["PATH"])
