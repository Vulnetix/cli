import os
import sys

~>DEBUG = bool(os.environ.get("APP_DEBUG"))
~>REQUIRE_TLS = not bool( os.getenv('DISABLE_TLS') )
~>ALLOW_SIGNUP = bool(os.environ["ALLOW_SIGNUP"])
~>VERBOSE = bool(sys.argv[2])


def confirm():
~>    return bool(input("Delete every backup? (yes/no) "))
