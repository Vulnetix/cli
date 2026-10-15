import os
import sys

retries = os.environ.get("RETRIES", "3")
~>if retries == 3:
    print("default retries")

~>if sys.argv[1] == 1:
    print("first mode")
