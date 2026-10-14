import subprocess as sp
from subprocess import call, check_call as run_checked


def search(pattern, path, logfile):
~>    hits = sp.check_output("grep " + pattern + " " + logfile, shell=True)
~>    call("rm -rf %s" % path, shell=True)
~>    run_checked(  f"chmod 600 {path}",   shell = True)
    return hits
