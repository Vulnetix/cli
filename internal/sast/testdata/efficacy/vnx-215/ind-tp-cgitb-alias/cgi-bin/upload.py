#!/usr/bin/env python3
import cgitb as tb
import os

~>tb.enable(format="text")

print("Content-Type: text/plain\n")
print(os.environ.get("QUERY_STRING", ""))
