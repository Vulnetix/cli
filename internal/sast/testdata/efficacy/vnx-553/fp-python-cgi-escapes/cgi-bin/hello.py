#!/usr/bin/env python3
import cgi
import html
import subprocess

form = cgi.FieldStorage()
name = form.getvalue("name", "world")
print("Content-Type: text/html\n")
print("<p>Hello, %s</p>" % html.escape(name))
uptime = subprocess.check_output(["uptime"])
print(html.escape(uptime.decode()))
