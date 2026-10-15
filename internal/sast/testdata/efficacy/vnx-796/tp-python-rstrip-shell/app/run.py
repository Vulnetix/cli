import subprocess


def run(arg):
~>    arg = arg.rstrip(";|&")
    subprocess.call("echo " + arg, shell=True)
