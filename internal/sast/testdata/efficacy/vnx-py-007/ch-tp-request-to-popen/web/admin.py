from subprocess import PIPE, Popen

from flask import request


def ping():
    host = request.form["host"]
~>    proc = Popen(args="ping -c 3 " + host, shell = True, stdout=PIPE)
    return proc.communicate()[0]
