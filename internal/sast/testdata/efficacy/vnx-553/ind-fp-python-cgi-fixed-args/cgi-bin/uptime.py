#!/usr/bin/env python3
import cgi
import html
import subprocess

print("Content-Type: text/html")
print()

form = cgi.FieldStorage()
label = form.getvalue("label", "server")
out = subprocess.run(["/usr/bin/uptime", "-p"], capture_output=True, text=True, check=False)
print("<p>{}: {}</p>".format(html.escape(label), html.escape(out.stdout)))
