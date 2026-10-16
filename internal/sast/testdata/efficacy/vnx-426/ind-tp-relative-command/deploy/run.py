import os
import subprocess


def generate(out):
~>    subprocess.check_output(["../tools/codegen", "--out", out])


def configure():
~>    os.system("./configure --prefix=/usr/local")


def migrate(db):
~>    proc = subprocess.Popen(
        ["bin/migrate", "--db", db],
        stdout=subprocess.PIPE,
    )
    return proc.communicate()
