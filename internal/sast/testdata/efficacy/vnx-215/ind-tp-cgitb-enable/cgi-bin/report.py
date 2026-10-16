#!/usr/bin/env python3
import cgi
import cgitb

~>cgitb.enable()

form = cgi.FieldStorage()
print("Content-Type: text/html\n")
print("<h1>Report for %s</h1>" % cgi.escape(form.getfirst("name", "")))
