#!/usr/bin/env python3
import cgitb
import os

cgitb.enable(display=0, logdir="/var/log/app/cgitb")

if os.environ.get("APP_DEBUG"):
    cgitb.enable()

print("Content-Type: text/plain\n")
print("ok")
