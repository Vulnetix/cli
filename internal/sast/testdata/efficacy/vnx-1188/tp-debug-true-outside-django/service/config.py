"""Runtime configuration for the reporting service."""

import os

~>DEBUG = True
~>DEBUG = os.environ.get("DEBUG", True)
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///reports.db")
