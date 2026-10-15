import logging
import os

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("t").info("env %s", os.environ)
