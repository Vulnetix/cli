#!/usr/bin/env python3
import cgi
import os

print("Content-Type: text/plain")
print()

form = cgi.FieldStorage()
domain = form.getvalue("domain", "example.org")
~>os.system("nslookup " + domain)
