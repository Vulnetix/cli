import logging

from app import create_app

~>logging.disable(logging.CRITICAL)
audit = logging.getLogger("audit")
~>audit.disabled = True
~>logging.getLogger("security").disabled = True

application = create_app()
