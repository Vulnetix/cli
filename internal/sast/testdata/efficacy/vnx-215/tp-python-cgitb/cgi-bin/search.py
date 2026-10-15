#!/usr/bin/env python3
import cgi
import cgitb

~>cgitb.enable()

form = cgi.FieldStorage()
print("Content-Type: text/html\n")
