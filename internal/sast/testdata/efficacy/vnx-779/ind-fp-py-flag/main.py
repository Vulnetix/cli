import logging
import os

level = logging.DEBUG if os.environ.get("VERBOSE") else logging.INFO
logging.basicConfig(level=level)
logging.getLogger("app.module").setLevel(logging.DEBUG)
print(os.environ["HOME"])
