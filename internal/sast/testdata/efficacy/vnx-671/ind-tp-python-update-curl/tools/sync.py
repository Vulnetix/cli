import os
import subprocess


def run():
~>    os.environ.update({"GIT_SSL_NO_VERIFY": "true"})
    subprocess.run(["git", "pull"], check=True)


def ca():
~>    os.environ["REQUESTS_CA_BUNDLE"] = ""
