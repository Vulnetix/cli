import os
import subprocess


def mirror(url):
~>    os.environ['GIT_SSL_NO_VERIFY'] = 'true'
~>    os.putenv("PYTHONHTTPSVERIFY", "0")
    subprocess.run(["git", "clone", url], check=True)
