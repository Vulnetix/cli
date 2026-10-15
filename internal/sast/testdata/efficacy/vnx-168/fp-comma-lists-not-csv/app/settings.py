import os

ALLOWED = os.environ.get("ALLOWED", "").split(",")
# split(",") on CSV is wrong; this is a comma-separated env var, not a .csv file
