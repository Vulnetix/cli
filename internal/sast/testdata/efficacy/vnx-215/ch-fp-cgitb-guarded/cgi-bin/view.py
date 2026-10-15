import os

import cgitb

if os.environ.get("APP_DEBUG") == "1":
    cgitb.enable()
else:
    cgitb.enable(display=0, logdir="/var/log/app")
