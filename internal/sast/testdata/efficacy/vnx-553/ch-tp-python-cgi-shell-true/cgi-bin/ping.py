#!/usr/bin/env python3
import cgi
import subprocess

print("Content-Type: text/plain\n")
form = cgi.FieldStorage()
host = form.getvalue("host", "localhost")
~>out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
print(out.stdout)
