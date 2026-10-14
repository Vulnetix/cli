import os
import stat
import subprocess
from pathlib import Path


def install(helper, path):
~>    os.chmod(helper, 0o4755)
~>    os.chmod(path, os.stat(path).st_mode | stat.S_ISUID)
~>    Path(helper).chmod(0o4750)
~>    subprocess.run(["chmod", "u+s", helper], check=True)
~>    os.system("chmod 4755 " + helper)
