import subprocess as sp
from subprocess import check_output


def go(command, pattern, logfile):
~>    process = sp.Popen(
        command,
        stdout=sp.PIPE,
        shell=True,
    )
~>    out = check_output("grep " + pattern + " " + logfile, shell=True)
    return process, out
