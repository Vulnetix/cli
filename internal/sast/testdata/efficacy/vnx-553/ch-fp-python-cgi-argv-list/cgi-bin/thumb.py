#!/usr/bin/env python3
import cgi
import re
import subprocess

print("Content-Type: text/plain\n")
form = cgi.FieldStorage()
name = form.getvalue("img", "")
if not re.fullmatch(r"[a-z0-9_-]+\.png", name):
    raise SystemExit("bad name")
subprocess.run(["/usr/bin/convert", "/srv/img/" + name, "-resize", "64x64", "/srv/thumbs/" + name], check=True)
print("ok")
