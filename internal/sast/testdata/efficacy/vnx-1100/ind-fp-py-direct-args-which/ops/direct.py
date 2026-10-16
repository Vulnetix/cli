#!/bin/bash
import shutil
import subprocess


def pack(path):
    subprocess.run(["tar", "czf", "out.tgz", path], check=True)


def has_bash():
    return shutil.which("bash") is not None


def listing(d):
    return subprocess.check_output(["ls", "-l", d])


def legacy(cmd):
    subprocess.run(cmd, shell=True)

# subprocess.run(["bash", "-c", "echo hi"])
