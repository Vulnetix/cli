import logging
import os

from app import create_app

if os.environ.get("QUIET"):
    pass

~>logging.disable(logging.CRITICAL)

application = create_app()
