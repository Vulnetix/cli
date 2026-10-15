import os

EXPORT_FORMAT = "csv"
EXPORT_COLUMNS = os.environ.get("EXPORT_COLUMNS", "id,name").split(",")
ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "").split(",")
CSV_EXPORT_DIR = settings.EXPORT_DIRS.split(",")
